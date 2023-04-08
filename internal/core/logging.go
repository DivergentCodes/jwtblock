package core

import (
	"encoding/json"
	"sync"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var once sync.Once
var zapLogger *zap.SugaredLogger

func initZapLogger() *zap.SugaredLogger {
	debug := viper.GetBool(OptStr_Debug)

	debugConfig := []byte(`{
		"level": "debug",
		"encoding": "json",
		"outputPaths": [
			"stdout",
			"/tmp/logs"
		],
		"errorOutputPaths": [
			"stderr"
		],
		"initialFields": {
		},
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"levelEncoder": "lowercase"
		}
	}`)

	standardConfig := []byte(`{
		"level": "info",
		"encoding": "json",
		"outputPaths": [
			"/tmp/logs"
		],
		"errorOutputPaths": [
			"stderr"
		],
		"initialFields": {
		},
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"levelEncoder": "lowercase"
		}
	}`)

	var cfg zap.Config
	var err error
	if debug {
		err = json.Unmarshal(debugConfig, &cfg)
	} else {
		err = json.Unmarshal(standardConfig, &cfg)
	}
	if err != nil {
		panic(err)
	}

	logger := zap.Must(cfg.Build())
	defer logger.Sync()

	return logger.Sugar()
}

// GetLogger returns a singleton of a configured zap logger.
func GetLogger() *zap.SugaredLogger {

	once.Do(func() {
		zapLogger = initZapLogger()
	})

	return zapLogger
}
