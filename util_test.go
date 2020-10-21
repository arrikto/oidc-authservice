package main

import (
	"fmt"
	"testing"

	"gonum.org/v1/gonum/stat"
	"gonum.org/v1/gonum/stat/distuv"
)

func TestCreateNonce_Simple(t *testing.T) {

	tests := []struct {
		name   string
		length int
	}{
		{name: "0", length: 0},
		{name: "32", length: 32},
		{name: "63", length: 63},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nonce, err := createNonce(test.length)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			t.Logf("Length: %d, Nonce: %s", test.length, nonce)
		})
	}
}

// TestCreateNonce_Distribution performs a statistical fitness test. Essentially,
// it tests that the nonce characters follow a uniform distribution.
// See: https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test
func TestCreateNonce_Distribution(t *testing.T) {

	nonce, err := createNonce(10000000)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	distribution := map[rune]int{}
	for _, nonceChar := range nonce {
		distribution[nonceChar]++
	}
	for k, v := range distribution {
		fmt.Printf("%v: %v\n", k, v)
	}

	// 1. Calculate the χ² statistic, a normalized sum of squared deviations
	// between observed and expected frequencies.
	var observed, expected []float64
	for _, v := range distribution {
		observed = append(observed, float64(v))
	}
	mean := stat.Mean(observed, nil)
	for range observed {
		expected = append(expected, mean)
	}
	chiSquare := stat.ChiSquare(observed, expected)

	// 2. Determine the degrees of freedom.
	// df = Cats − Parms, where Cats is the number of observation categories
	// recognized by the model, and Parms is the number of parameters in the
	// model adjusted to make the model best fit the observations.
	// In this case, Cats=len(observed) and Parms=1
	// See: https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test#Discrete_uniform_distribution
	df := len(observed) - 1

	// 3. Select a level of confidence, p.
	p := 0.95

	// 4. Compare χ² to the critical value from the chi-squared distribution
	// with df degrees of freedom and the selected confidence level.
	chiSquaredDist := distuv.ChiSquared{
		K: float64(df),
	}

	// 5. Test null hypothesis, that observed follows the uniform distribution.
	threshold := chiSquaredDist.Quantile(p)
	t.Logf("Test: %v, Threshold: %v", chiSquare, threshold)
	nullHypothesis := chiSquare < threshold

	if !nullHypothesis {
		t.Fatalf("Nonce characters don't seem to follow a uniform distribution")
	}
}
