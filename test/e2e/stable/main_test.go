package tests

import (
	"testing"

	"github.com/httprunner/httprunner/v4/hrp"
)

func TestDemo(t *testing.T) {
	tc := &hrp.TestCase{
		Config: hrp.NewConfig("Test Demo").
			SetCaseTimeout(1).
			SetRequestTimeout(1).
			// WithParameters(map[string]interface{}{"limit": 1}).
			// ParametersSetting: &TParamsConfig{
			// 	Limit: 4, // limit could be less than total
			// },
			SetBaseURL("http://192.168.152.146:9000").
			SetThinkTime(
				"multiply",
				nil,
				// map[string]float64{"min_percentage": 1, "max_percentage": 1},
				0),
		TestSteps: []hrp.IStep{
			// hrp.NewStep("transation 1 start").
			// 	StartTransaction("trans1"),
			hrp.NewStep("headers").
				// Loop(3).
				GET("/zjzhang").
				// SetTimeout(time.Second).
				Validate().
				AssertEqual("status_code", 200, "check status code"),
			// .AssertEqual("headers.\"Content-Type\"", "application/json", "check http response Content-Type"),
			// hrp.NewStep("transation 1 end").
			// 	EndTransaction("trans1"),
			// hrp.NewStep("think time1").
			// 	SetThinkTime(1),
			// hrp.NewStep("user-agent").
			// 	GET("/user-agent").
			// 	Validate().
			// 	AssertEqual("status_code", 200, "check status code").
			// 	AssertEqual("headers.\"Content-Type\"", "application/json", "check http response Content-Type"),
			// hrp.NewStep("rendezvous 1").
			// 	SetRendezvous("rend1").
			// 	WithUserPercent(0.8).
			// 	WithTimeout(3000),
			// hrp.NewStep("TestCaseRef").
			// 	CallRefCase(&hrp.TestCase{Config: hrp.NewConfig("TestCase2")}),
		},
	}
	// tc.Config.ParametersSetting = &hrp.TParamsConfig{Limit: 1}

	// b := hrp.NewStandaloneBoomer(1, 1) //spawn_count: 1000, spawn_rate: 100
	r := hrp.NewRunner(t).SetSaveTests(false)
	cr, err := r.NewCaseRunner(tc)
	if err != nil {
		t.Errorf("new case runner error: %v", err)
	}

	for i := 0; i < 5; i++ {
		sr := cr.NewSession()
		if err = sr.Start(nil); err != nil {
			t.Errorf("start session error: %v", err)
		}
		s, err := sr.GetSummary()
		if err != nil {
			t.Errorf("get summary error: %v", err)
		}
		for _, r := range s.Records {
			t.Logf("record success: %v", r.Success)
		}
	}

	// sr := cr.NewSession()
	// sr.Start()
	// if err := r.Run(tc); err != nil {
	// 	t.Errorf("run test case error: %v", err)
	// }
	// r.
	// if err := hrp.Run(t, tc); err != nil {
	// 	t.Errorf("run test case error: %v", err)
	// }
	// b.AddOutput(boomer.NewConsoleOutput())
	// go b.Run(tc)
	// time.Sleep(5 * time.Second) //expected running time
	// b.Quit()
}
