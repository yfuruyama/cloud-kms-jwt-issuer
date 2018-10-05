package app

import "os"

type Config struct {
	KeyResourceId string
}

func GetConfig() Config {
	return Config{
		KeyResourceId: os.Getenv("KEY_RESOURCE_ID"),
	}
}
