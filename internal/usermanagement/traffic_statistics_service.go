package usermanagement

import (
	"context"
	"sort"
	"strings"
	"time"
)

const (
	trafficDateLayout = "2006-01-02"
	trafficHourLayout = "2006-01-02T15:00:00"
)

type TrafficStatisticsService struct {
	users  UserStore
	ledger UsageLedgerStore
	now    func() time.Time
}

func NewTrafficStatisticsService(users UserStore, ledger UsageLedgerStore) *TrafficStatisticsService {
	return &TrafficStatisticsService{users: users, ledger: ledger, now: time.Now}
}

func (s *TrafficStatisticsService) Statistics(ctx context.Context, query TrafficStatisticsQuery) (*TrafficStatistics, error) {
	if s == nil || s.users == nil || s.ledger == nil {
		return nil, ErrInvalid
	}
	loc, err := trafficLocation(query.TimeZone)
	if err != nil {
		return nil, err
	}
	granularity := query.Granularity
	if granularity == "" {
		granularity = TrafficGranularityDay
	}
	if granularity != TrafficGranularityDay && granularity != TrafficGranularityHour {
		return nil, invalid("invalid traffic granularity %q", granularity)
	}
	start, end, startDate, endDate, err := trafficPeriod(query, granularity, s.now(), loc)
	if err != nil {
		return nil, err
	}
	groupBy := query.GroupBy
	if groupBy == "" {
		groupBy = TrafficGroupByModel
	}
	if groupBy != TrafficGroupByModel && groupBy != TrafficGroupByProvider {
		return nil, invalid("invalid traffic group by %q", groupBy)
	}
	if query.Status != "" && !query.Status.IsValid() {
		return nil, invalid("invalid traffic status %q", query.Status)
	}

	rows, err := s.ledger.ListUsageLedgerRows(ctx, UsageLedgerFilter{
		UserID:   query.UserID,
		Provider: query.Provider,
		Model:    query.Model,
		Status:   query.Status,
		From:     start,
		To:       end,
	})
	if err != nil {
		return nil, err
	}
	users, err := s.users.ListUsers(ctx, UserFilter{})
	if err != nil {
		return nil, err
	}
	userByID := make(map[UserID]User, len(users))
	for _, user := range users {
		userByID[user.ID] = user
	}

	daily := make(map[string]*trafficAggregate)
	series := make(map[string]*trafficSeriesAggregate)
	ranking := make(map[UserID]*trafficUserAggregate)
	userSeries := make(map[UserID]map[string]*trafficSeriesAggregate)
	providers := make(map[string]struct{})
	models := make(map[string]struct{})
	activeUsers := make(map[UserID]struct{})
	result := &TrafficStatistics{
		PeriodStart: startDate.Format(trafficDateLayout),
		PeriodEnd:   endDate.Format(trafficDateLayout),
		TimeZone:    loc.String(),
		Granularity: string(granularity),
	}

	for date := startDate; date.Before(end); date = trafficNextBucket(date, granularity) {
		daily[trafficBucketKey(date, granularity)] = &trafficAggregate{}
	}
	for _, row := range rows {
		day := trafficBucketKey(row.CreatedAt.In(loc), granularity)
		dailyTotal, ok := daily[day]
		if !ok {
			dailyTotal = &trafficAggregate{}
			daily[day] = dailyTotal
		}
		tokens, estimated := usageTotalTokens(row)
		result.HasEstimatedTotal = result.HasEstimatedTotal || estimated
		dailyTotal.add(tokens, row.CreditCost, row.Status)
		result.Summary.TotalTokens += tokens
		result.Summary.TotalCredits += row.CreditCost
		result.Summary.Requests++
		if row.Status == UsageStatusFailed {
			result.Summary.Failed++
		}
		activeUsers[row.UserID] = struct{}{}
		providers[row.Provider] = struct{}{}
		models[row.Model] = struct{}{}

		userTotal := ranking[row.UserID]
		if userTotal == nil {
			userTotal = &trafficUserAggregate{UserID: row.UserID}
			ranking[row.UserID] = userTotal
		}
		userTotal.add(tokens, row.CreditCost)

		seriesKey, provider, model := trafficSeriesKey(groupBy, row.Provider, row.Model)
		modelTotal := series[seriesKey]
		if modelTotal == nil {
			modelTotal = &trafficSeriesAggregate{Key: seriesKey, Provider: provider, Model: model}
			series[seriesKey] = modelTotal
		}
		modelTotal.add(day, tokens, row.CreditCost, row.Status)

		userSeriesTotals := userSeries[row.UserID]
		if userSeriesTotals == nil {
			userSeriesTotals = make(map[string]*trafficSeriesAggregate)
			userSeries[row.UserID] = userSeriesTotals
		}
		userModelTotal := userSeriesTotals[seriesKey]
		if userModelTotal == nil {
			userModelTotal = &trafficSeriesAggregate{Key: seriesKey, Provider: provider, Model: model}
			userSeriesTotals[seriesKey] = userModelTotal
		}
		userModelTotal.add(day, tokens, row.CreditCost, row.Status)
	}
	result.Summary.ActiveUsers = int64(len(activeUsers))
	localEndExclusive := endDate.AddDate(0, 0, 1)
	result.Daily = trafficDailyPoints(daily, startDate, localEndExclusive, granularity)
	result.Providers = sortedStrings(providers)
	result.Models = sortedStrings(models)
	result.Series = trafficSeries(series, startDate, localEndExclusive, 5, granularity)

	if query.UserID == "" {
		result.Ranking = make([]TrafficUserRanking, 0, len(ranking))
		for _, total := range ranking {
			user := userByID[total.UserID]
			result.Ranking = append(result.Ranking, TrafficUserRanking{
				UserID:       total.UserID,
				Username:     user.Username,
				DisplayName:  user.DisplayName,
				TotalTokens:  total.TotalTokens,
				TotalCredits: total.TotalCredits,
				Requests:     total.Requests,
				Series:       trafficUserSeries(userSeries[total.UserID], 5),
			})
		}
		sort.SliceStable(result.Ranking, func(i, j int) bool {
			if result.Ranking[i].TotalTokens != result.Ranking[j].TotalTokens {
				return result.Ranking[i].TotalTokens > result.Ranking[j].TotalTokens
			}
			if result.Ranking[i].TotalCredits != result.Ranking[j].TotalCredits {
				return result.Ranking[i].TotalCredits > result.Ranking[j].TotalCredits
			}
			return strings.ToLower(result.Ranking[i].Username) < strings.ToLower(result.Ranking[j].Username)
		})
	}
	return result, nil
}

type trafficAggregate struct {
	TotalTokens  int64
	TotalCredits int64
	Requests     int64
}

func (a *trafficAggregate) add(tokens, credits int64, _ UsageStatus) {
	a.TotalTokens += tokens
	a.TotalCredits += credits
	a.Requests++
}

type trafficUserAggregate struct {
	UserID       UserID
	TotalTokens  int64
	TotalCredits int64
	Requests     int64
}

func (a *trafficUserAggregate) add(tokens, credits int64) {
	a.TotalTokens += tokens
	a.TotalCredits += credits
	a.Requests++
}

type trafficSeriesAggregate struct {
	Key          string
	Provider     string
	Model        string
	Other        bool
	TotalTokens  int64
	TotalCredits int64
	Requests     int64
	Points       map[string]*trafficAggregate
}

func (a *trafficSeriesAggregate) add(day string, tokens, credits int64, status UsageStatus) {
	a.TotalTokens += tokens
	a.TotalCredits += credits
	a.Requests++
	if a.Points == nil {
		a.Points = make(map[string]*trafficAggregate)
	}
	point := a.Points[day]
	if point == nil {
		point = &trafficAggregate{}
		a.Points[day] = point
	}
	point.add(tokens, credits, status)
}

func trafficLocation(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, invalid("traffic time zone is required")
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, invalid("invalid traffic time zone %q", name)
	}
	return loc, nil
}

func trafficBucketKey(t time.Time, granularity TrafficGranularity) string {
	if granularity == TrafficGranularityHour {
		return t.Truncate(time.Hour).Format(trafficHourLayout)
	}
	return t.Format(trafficDateLayout)
}

func trafficNextBucket(t time.Time, granularity TrafficGranularity) time.Time {
	if granularity == TrafficGranularityHour {
		return t.Add(time.Hour)
	}
	return t.AddDate(0, 0, 1)
}

func trafficPeriod(query TrafficStatisticsQuery, granularity TrafficGranularity, now time.Time, loc *time.Location) (time.Time, time.Time, time.Time, time.Time, error) {
	localNow := now.In(loc)
	startDate := time.Date(localNow.Year(), localNow.Month(), 1, 0, 0, 0, 0, loc)
	endDate := startDate.AddDate(0, 1, -1)
	if strings.TrimSpace(query.From) != "" || strings.TrimSpace(query.To) != "" {
		var err error
		if strings.TrimSpace(query.From) != "" {
			startDate, err = time.ParseInLocation(trafficDateLayout, strings.TrimSpace(query.From), loc)
			if err != nil {
				return time.Time{}, time.Time{}, time.Time{}, time.Time{}, invalid("invalid traffic from date")
			}
		}
		if strings.TrimSpace(query.To) != "" {
			endDate, err = time.ParseInLocation(trafficDateLayout, strings.TrimSpace(query.To), loc)
			if err != nil {
				return time.Time{}, time.Time{}, time.Time{}, time.Time{}, invalid("invalid traffic to date")
			}
		} else {
			endDate = startDate
		}
	}
	if endDate.Before(startDate) {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, invalid("traffic end date must not precede start date")
	}
	if granularity == TrafficGranularityHour && !endDate.Equal(startDate) {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, invalid("traffic hour granularity requires a single day range")
	}
	endExclusive := endDate.AddDate(0, 0, 1)
	days := 0
	for date := startDate; date.Before(endExclusive); date = date.AddDate(0, 0, 1) {
		days++
	}
	if days > 31 {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, invalid("traffic date range cannot exceed 31 days")
	}
	return startDate.UTC(), endExclusive.UTC(), startDate, endDate, nil
}

func usageTotalTokens(row UsageLedgerRow) (int64, bool) {
	if row.TotalTokens > 0 {
		return row.TotalTokens, false
	}
	return row.InputTokens + row.OutputTokens + row.ReasoningTokens, true
}

func trafficSeriesKey(groupBy TrafficGroupBy, provider, model string) (string, string, string) {
	if groupBy == TrafficGroupByProvider {
		return "provider:" + provider, provider, ""
	}
	return "model:" + provider + "\x00" + model, provider, model
}

func trafficDailyPoints(values map[string]*trafficAggregate, start, end time.Time, granularity TrafficGranularity) []TrafficDailyPoint {
	points := make([]TrafficDailyPoint, 0)
	for date := start; date.Before(end); date = trafficNextBucket(date, granularity) {
		key := trafficBucketKey(date, granularity)
		value := values[key]
		if value == nil {
			value = &trafficAggregate{}
		}
		points = append(points, TrafficDailyPoint{Date: key, TotalTokens: value.TotalTokens, TotalCredits: value.TotalCredits, Requests: value.Requests})
	}
	return points
}

func trafficSeries(values map[string]*trafficSeriesAggregate, start, end time.Time, limit int, granularity TrafficGranularity) []TrafficModelSeries {
	all := make([]*trafficSeriesAggregate, 0, len(values))
	for _, value := range values {
		all = append(all, value)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].TotalTokens != all[j].TotalTokens {
			return all[i].TotalTokens > all[j].TotalTokens
		}
		return all[i].Key < all[j].Key
	})
	if limit <= 0 || len(all) <= limit {
		limit = len(all)
	}
	visible := all[:limit]
	other := &trafficSeriesAggregate{Key: "other", Other: true}
	for _, value := range all[limit:] {
		for day, point := range value.Points {
			other.add(day, point.TotalTokens, point.TotalCredits, "")
		}
	}
	if len(all) > limit {
		visible = append(visible, other)
	}
	result := make([]TrafficModelSeries, 0, len(visible))
	for _, value := range visible {
		points := value.Points
		if value.Other {
			points = value.Points
		}
		result = append(result, TrafficModelSeries{
			Key:          value.Key,
			Provider:     value.Provider,
			Model:        value.Model,
			Other:        value.Other,
			TotalTokens:  value.TotalTokens,
			TotalCredits: value.TotalCredits,
			Requests:     value.Requests,
			Points:       trafficDailyPoints(points, start, end, granularity),
		})
	}
	return result
}

func trafficUserSeries(values map[string]*trafficSeriesAggregate, limit int) []TrafficUserRankingSeries {
	all := make([]*trafficSeriesAggregate, 0, len(values))
	for _, value := range values {
		all = append(all, value)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].TotalTokens != all[j].TotalTokens {
			return all[i].TotalTokens > all[j].TotalTokens
		}
		return all[i].Key < all[j].Key
	})
	if limit <= 0 || len(all) <= limit {
		limit = len(all)
	}
	visible := all[:limit]
	other := &trafficSeriesAggregate{Key: "other", Other: true}
	for _, value := range all[limit:] {
		other.TotalTokens += value.TotalTokens
		other.TotalCredits += value.TotalCredits
		other.Requests += value.Requests
	}
	if len(all) > limit {
		visible = append(visible, other)
	}
	result := make([]TrafficUserRankingSeries, 0, len(visible))
	for _, value := range visible {
		result = append(result, TrafficUserRankingSeries{
			Key:          value.Key,
			Provider:     value.Provider,
			Model:        value.Model,
			Other:        value.Other,
			TotalTokens:  value.TotalTokens,
			TotalCredits: value.TotalCredits,
			Requests:     value.Requests,
		})
	}
	return result
}

func sortedStrings(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
