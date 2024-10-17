package http

import (
	"fmt"
	"testing"
	"time"

	"github.com/httprunner/httprunner/v4/hrp"
)

type Result struct {
	*hrp.StepResult
	Timestamp time.Time `json:"timestamp"`
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
	for i := 1; i <= loop; i++ {
		sr := cr.NewSession()
		startTime := time.Now()
		result := &Result{
			Timestamp: startTime,
			StepResult: &hrp.StepResult{
				Name:      fmt.Sprintf("%s - %d", tc.Config.Name, i),
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
				summary.Records[0].Name = result.Name
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
			// now := time.Now()
			time.Sleep(time.Duration((int64(interval) - summary.Records[0].Elapsed)) * time.Millisecond)
			// t.Logf("sleep %d ms", time.Since(now).Milliseconds())
		}
	}

	return failureRecords, nil
}
