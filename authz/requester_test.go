package authz

import (
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/stretchr/testify/assert"
)

// TestBeyondTight: security 03's two-person rule on the last applied facts: beyond T_tight, without a watermark, or on
// a stalled source.
func TestBeyondTight(t *testing.T) {
	tight := time.Hour
	at := func(state string, has bool, age time.Duration) projection.Judgement {
		return projection.Judgement{SourceState: state, HasWatermark: has, Age: age}
	}
	assert.False(t, beyondTight(at(projection.Aligned, true, 10*time.Minute), tight), "within T_tight: one person")
	assert.False(t, beyondTight(at(projection.Aligned, true, tight), tight), "at T_tight: still one")
	assert.True(t, beyondTight(at(projection.Aligned, true, tight+time.Second), tight), "beyond T_tight")
	assert.True(t, beyondTight(at(projection.Aligned, false, 0), tight), "no watermark: the age is unknown")
	assert.True(t, beyondTight(at(projection.Stalled, true, time.Minute), tight), "stalled: facts from before a rollback")
}
