package http

import (
	"fmt"
	"testing"
	"time"

	"github.com/httprunner/httprunner/v4/hrp"
	"github.com/rs/zerolog"
)

type Result struct {
	Index     int
	Timestamp time.Time `json:"timestamp"`
	*hrp.StepResult
}

func init() {
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
}

func Loop(t *testing.T, name, url, method string, loop, interval, requestTimeout, expectedStatusCode int) ([]*Result, error) {
	tc := &hrp.TestCase{
		Config: hrp.NewConfig(name).SetRequestTimeout(float32(requestTimeout) / 1000),
		TestSteps: []hrp.IStep{
			hrp.NewStep(method).GET(url).Validate().AssertEqual("status_code", expectedStatusCode, "check status code"),
		},
	}

	cr, err := hrp.NewRunner(t).SetFailfast(false).NewCaseRunner(tc)
	if err != nil {
		return nil, fmt.Errorf("failed to create new case runner: %w", err)
	}

	var failureRecords []*Result
	for i := 0; i < loop; i++ {
		sr := cr.NewSession()
		startTime := time.Now()
		result := &Result{
			Index:     i,
			Timestamp: startTime,
			StepResult: &hrp.StepResult{
				Name:      tc.Config.Name,
				Success:   false,
				StartTime: startTime.Unix(),
			},
		}
		if err = sr.Start(nil); err != nil {
			result.Elapsed = int64(time.Since(startTime).Milliseconds())
			result.Attachments = fmt.Errorf("failed to start session: %w", err).Error()
			failureRecords = append(failureRecords, result)
			continue
		}

		summary, err := sr.GetSummary()
		if err != nil {
			result.Elapsed = int64(time.Since(startTime).Milliseconds())
			result.Attachments = fmt.Errorf("failed to get session summary: %w", err).Error()
			failureRecords = append(failureRecords, result)
			continue
		}

		if !summary.Success {
			if len(summary.Records) != 0 {
				result.StepResult = summary.Records[0]
			} else {
				result.Elapsed = int64(time.Since(startTime).Milliseconds())
				result.Attachments = "unexpected empty summary records"
				failureRecords = append(failureRecords, result)
			}
			failureRecords = append(failureRecords, result)
			continue
		}

		if len(summary.Records) != 1 {
			result.Elapsed = int64(time.Since(startTime).Milliseconds())
			result.Attachments = fmt.Sprintf("record count should be 1, but got %#v", summary.Records)
			failureRecords = append(failureRecords, result)
			continue
		}

		if summary.Records[0].Success && summary.Records[0].Elapsed < int64(interval) {
			time.Sleep(time.Duration((int64(interval) - summary.Records[0].Elapsed)) * time.Millisecond)
		}
	}

	return failureRecords, nil
}
