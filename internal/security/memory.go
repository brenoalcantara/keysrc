package security

import "runtime"

func ZeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}

	runtime.KeepAlive(value)
}
