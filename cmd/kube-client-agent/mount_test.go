package main

import "testing"

func Test_getSecretName(t *testing.T) {
	type args struct {
		commonName string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "server test case",
			args: args{
				commonName: "system:etcd-server:etcd-0.foo.bar",
			},
			want: "server-etcd-0.foo.bar",
		},
		{
			name: "peer test case",
			args: args{
				commonName: "system:etcd-peer:etcd-0.foo.bar",
			},
			want: "peer-etcd-0.foo.bar",
		},
		{
			name: "metric test case",
			args: args{
				commonName: "system:etcd-metric:etcd-0.foo.bar",
			},
			want: "metric-etcd-0.foo.bar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSecretName(tt.args.commonName); got != tt.want {
				t.Errorf("getSecretName() = %v, want %v", got, tt.want)
			}
		})
	}
}
