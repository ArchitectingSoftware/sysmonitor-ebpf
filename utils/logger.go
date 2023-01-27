package utils

import (
	"os"
	"path/filepath"

	"github.com/denisbrodbeck/machineid"
	"github.com/lithammer/shortuuid/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type EventLogger struct {
	logger      *zap.Logger
	canLog      bool
	machineID   string
	processName string
}

func NewEventLogger() (EventLogger, error) {
	l := EventLogger{
		canLog:      true,
		processName: filepath.Base(os.Args[0]),
	}

	if !LoggingEnabledFlag {
		l.canLog = false
		return l, nil
	}

	/*
		logger, err := zap.NewProduction()
		defer logger.Sync()
		if err != nil {
			l.canLog = false
			return l, err
		}
		l.logger = logger
		return l, nil
	*/
	w := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "/var/log/" + l.processName + "/" + LogNameFlag,
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
	})
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		w,
		zap.InfoLevel,
	)

	logger := zap.New(core)
	defer logger.Sync()
	l.logger = logger

	//now get the machine id, use hostname if unable to get
	id, err := machineid.ID()
	if err != nil {
		//next try host name
		id, err = os.Hostname()
		if err != nil {
			//if that is not available generate a short UUID
			id = shortuuid.New()
		}
	}
	l.machineID = id

	return l, nil
}

func (e *EventLogger) WriteSysCallEvent(cnt int, k []uint32, v []uint64) {
	if !e.canLog {
		return
	}
	e.logger.Info("type/sc",
		zap.String("mid", e.machineID),
		zap.Int("cnt", cnt),
		zap.Uint32s("keys", k[:cnt]),
		zap.Uint64s("vals", v[:cnt]),
	)
}
