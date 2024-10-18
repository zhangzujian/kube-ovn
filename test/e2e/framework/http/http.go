package http

import (
	"fmt"
	"testing"
	"time"

	"github.com/httprunner/httprunner/v4/hrp"
)

func Loop(t *testing.T, name, url, method string, loop, interval, requestTimeout int, expectedStatusCode int) ([]*hrp.StepResult, error) {
	tc := &hrp.TestCase{
		Config: hrp.NewConfig(name).SetRequestTimeout(float32(requestTimeout) / 1000), //.SetBaseURL(url),
		TestSteps: []hrp.IStep{
			hrp.NewStep(method).GET(url).Validate().AssertEqual("status_code", expectedStatusCode, "check status code"),
		},
	}

	cr, err := hrp.NewRunner(t).SetFailfast(false).NewCaseRunner(tc)
	if err != nil {
		return nil, fmt.Errorf("failed to create new case runner: %w", err)
	}

	var failureRecords []*hrp.StepResult
	for i := 1; i <= loop; i++ {
		sr := cr.NewSession()
		startTime := time.Now()
		if err = sr.Start(nil); err != nil {
			failureRecords = append(failureRecords, &hrp.StepResult{
				Name:        fmt.Sprintf("%s - %d", tc.Config.Name, i),
				Success:     false,
				StartTime:   startTime.Unix(),
				Elapsed:     int64(time.Since(startTime).Milliseconds()),
				Attachments: fmt.Errorf("failed to start session: %w", err).Error(),
			})
			continue
		}

		summary, err := sr.GetSummary()
		if err != nil {
			failureRecords = append(failureRecords, &hrp.StepResult{
				Name:        fmt.Sprintf("%s - %d", tc.Config.Name, i),
				Success:     false,
				StartTime:   startTime.Unix(),
				Elapsed:     int64(time.Since(startTime).Milliseconds()),
				Attachments: fmt.Errorf("failed to get session summary: %w", err).Error(),
			})
			continue
		}

		if !summary.Success {
			if len(summary.Records) != 0 {
				failureRecords = append(failureRecords, summary.Records...)
			} else {
				failureRecords = append(failureRecords, &hrp.StepResult{
					Name:        fmt.Sprintf("%s - %d", tc.Config.Name, i),
					Success:     false,
					StartTime:   startTime.Unix(),
					Elapsed:     int64(time.Since(startTime).Milliseconds()),
					Attachments: "unexpected empty summary records",
				})
			}
			continue
		}

		if len(summary.Records) != 1 {
			failureRecords = append(failureRecords, &hrp.StepResult{
				Name:        fmt.Sprintf("%s - %d", tc.Config.Name, i),
				Success:     false,
				StartTime:   startTime.Unix(),
				Elapsed:     int64(time.Since(startTime).Milliseconds()),
				Attachments: fmt.Sprintf("record count should be 1, but got %#v", summary.Records),
			})
			continue
		}

		if summary.Records[0].Success && summary.Records[0].Elapsed < int64(interval) {
			time.Sleep(time.Duration((int64(interval) - summary.Records[0].Elapsed)) * time.Millisecond)
		}
	}

	return failureRecords, nil
}
