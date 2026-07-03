package app

type Config struct {
	ID           string
	Name         string
	WindowWidth  float32
	WindowHeight float32
}

func DefaultConfig() Config {
	return Config{
		ID:           "br.dev.keysrc",
		Name:         "KeySrc",
		WindowWidth:  960,
		WindowHeight: 640,
	}
}
