package aws

import (
	"fmt"
	"testing"
)

func TestAZtoRegion(t *testing.T) {
	cases := []struct {
		az     string
		region string
		err    bool
	}{{
		az:     "",
		region: "",
		err:    true,
	}, {
		az:     "us-west-1a",
		region: "us-west-1",
		err:    false,
	}}

	for idx, c := range cases {
		t.Run(fmt.Sprintf("test case #%d", idx), func(t *testing.T) {
			r, err := azToRegion(c.az)
			if err != nil && !c.err {
				t.Errorf("err expected: %v, got: %v", c.err, err)
			}

			if r != c.region {
				t.Errorf("region expected: %v, got %v", c.region, r)
			}
		})
	}
}
