package http

import (
	"fmt"
	"testing"
	"time"

	"github.com/httprunner/httprunner/v4/hrp"
	"github.com/rs/zerolog"
)

type Report struct {
	Index     int
	Timestamp time.Time `json:"timestamp"`
	*hrp.StepResult
}

func init() {
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
}

func runCaseOnce(runner *hrp.CaseRunner) (failure *Report) {
	session := runner.NewSession()
	startTime := time.Now()
	failure = &Report{
		Timestamp: startTime,
		StepResult: &hrp.StepResult{
			Success:   false,
			StartTime: startTime.Unix(),
		},
	}
	if err := session.Start(nil); err != nil {
		failure.Elapsed = int64(time.Since(startTime).Milliseconds())
		failure.Attachments = fmt.Errorf("failed to start session: %w", err).Error()
		return
	}

	summary, err := session.GetSummary()
	if err != nil {
		failure.Elapsed = int64(time.Since(startTime).Milliseconds())
		failure.Attachments = fmt.Errorf("failed to get session summary: %w", err).Error()
		return
	}

	if !summary.Success {
		if len(summary.Records) != 0 {
			failure.StepResult = summary.Records[0]
		} else {
			failure.Elapsed = int64(time.Since(startTime).Milliseconds())
			failure.Attachments = "unexpected empty summary records"
		}
		return
	}

	if len(summary.Records) != 1 {
		failure.Elapsed = int64(time.Since(startTime).Milliseconds())
		failure.Attachments = fmt.Sprintf("record count should be 1, but got %#v", summary.Records)
	}

	return nil
}

func Loop(t *testing.T, name, url, method string, count, interval, requestTimeout, expectedStatusCode int, stopCh <-chan struct{}) ([]*Report, error) {
	tc := &hrp.TestCase{
		Config: hrp.NewConfig(name).SetRequestTimeout(float32(requestTimeout) / 1000),
		TestSteps: []hrp.IStep{
			hrp.NewStep(method).GET(url).Validate().AssertEqual("status_code", expectedStatusCode, "check status code"),
		},
	}

	runner, err := hrp.NewRunner(t).SetFailfast(false).NewCaseRunner(tc)
	if err != nil {
		return nil, fmt.Errorf("failed to create new case runner: %w", err)
	}

	var failures []*Report
LOOP:
	for i := 0; i < count; i++ {
		if stopCh != nil {
			select {
			case <-stopCh:
				break LOOP
			default:
			}
		}

		result := runCaseOnce(runner)
		if result != nil {
			result.Index, result.Name = i, name
			failures = append(failures, result)
		} else {
			time.Sleep(time.Now().Add(time.Duration(interval) * time.Millisecond).Sub(time.Now()))
		}
	}

	return failures, nil
}
