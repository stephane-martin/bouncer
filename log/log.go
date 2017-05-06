package log

import (
	"os"

	"github.com/Sirupsen/logrus"
)

var Log = logrus.New()
var RequestLog = logrus.New()

func init() {
	Log.Out = os.Stderr
	RequestLog.Out = os.Stdout
}
