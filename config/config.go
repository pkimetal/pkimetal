package config

import (
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/pkimetal/pkimetal/logger"

	"github.com/spf13/viper"

	"go.uber.org/zap"
)

type config struct {
	Server struct {
		WebserverPort       int           `mapstructure:"webserverPort"`
		MonitoringPort      int           `mapstructure:"monitoringPort"`
		ReadTimeout         time.Duration `mapstructure:"readTimeout"`
		IdleTimeout         time.Duration `mapstructure:"idleTimeout"`
		DisableKeepalive    bool          `mapstructure:"disableKeepalive"`
		RequestTimeout      time.Duration `mapstructure:"requestTimeout"`
		LivezTimeout        time.Duration `mapstructure:"livezTimeout"`
		ReadyzTimeout       time.Duration `mapstructure:"readyzTimeout"`
		RememberBusyTimeout time.Duration `mapstructure:"rememberBusyTimeout"`
		MetricsTimeout      time.Duration `mapstructure:"metricsTimeout"`
	}
	Linter struct {
		MaxQueueSize int `mapstructure:"maxQueueSize"`
		Badkeys      struct {
			NumProcesses int    `mapstructure:"numProcesses"`
			PythonDir    string `mapstructure:"pythonDir"`
		}
		Certlint struct {
			NumProcesses int `mapstructure:"numProcesses"`
			RubyDir      string
		}
		Dwklint struct {
			NumGoroutines int    `mapstructure:"numGoroutines"`
			BlocklistDir  string `mapstructure:"blocklistDir"`
		}
		Ftfy struct {
			NumProcesses int    `mapstructure:"numProcesses"`
			PythonDir    string `mapstructure:"pythonDir"`
		}
		Pkilint struct {
			NumProcesses int    `mapstructure:"numProcesses"`
			PythonDir    string `mapstructure:"pythonDir"`
		}
		Rocacheck struct {
			NumGoroutines int `mapstructure:"numGoroutines"`
		}
		X509lint struct {
			NumGoroutines int `mapstructure:"numGoroutines"`
		}
		Zlint struct {
			NumGoroutines int `mapstructure:"numGoroutines"`
		}
	}
	Response struct {
		DefaultFormat   string `mapstructure:"defaultFormat"`
		JsonPrettyPrint bool   `mapstructure:"jsonPrettyPrint"`
	}
	Logging struct {
		IsDevelopment      bool   `mapstructure:"isDevelopment"`
		Level              string `mapstructure:"level"`
		SamplingInitial    int    `mapstructure:"samplingInitial"`
		SamplingThereafter int    `mapstructure:"samplingThereafter"`
	}
}

type ResponseFormat int

const (
	RESPONSEFORMAT_HTML ResponseFormat = iota
	RESPONSEFORMAT_JSON
	RESPONSEFORMAT_TEXT
)

var (
	ApplicationName       string
	ApplicationNamespace  string
	Config                config
	DefaultResponseFormat = RESPONSEFORMAT_JSON

	// Automatically populated by the build system (see Makefile / Dockerfile).
	BuildTimestamp                              string
	Vcs, VcsModified, VcsRevision, VcsTimestamp string
	PkimetalVersion                             string
)

func init() {
	// Determine the application name and namespace.
	if path, err := os.Executable(); err != nil {
		panic(err)
	} else {
		ApplicationName = path[strings.LastIndex(path, "/")+1:]
		ApplicationNamespace = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(ApplicationName, "-", ""), "_", ""))
	}

	// Initialize Viper and Logger.
	if err := initViper(); err != nil {
		panic(err)
	} else if err = logger.InitLogger(Config.Logging.IsDevelopment, Config.Logging.Level, Config.Logging.SamplingInitial, Config.Logging.SamplingThereafter); err != nil {
		panic(err)
	}

	// Check the default response format.
	if DefaultResponseFormat = ParseResponseFormat(Config.Response.DefaultFormat); DefaultResponseFormat == -1 {
		panic(fmt.Sprintf("Invalid default response format: %s", Config.Response.DefaultFormat))
	}

	// Log build information.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, bs := range bi.Settings {
			switch bs.Key {
			case "vcs":
				Vcs = bs.Value
			case "vcs.modified":
				VcsModified = bs.Value
			case "vcs.revision":
				VcsRevision = bs.Value
			case "vcs.time":
				VcsTimestamp = bs.Value
			}
		}
		logger.Logger.Info(
			"Build information",
			zap.String("build_timestamp", BuildTimestamp),
			zap.String("vcs", Vcs),
			zap.String("vcs_modified", VcsModified),
			zap.String("vcs_revision", VcsRevision),
			zap.String("vcs_timestamp", VcsTimestamp),
		)
	}

	if PkimetalVersion == "" {
		PkimetalVersion = VcsRevision
	}

	// Log RLIMIT_NOFILE soft and hard limits.
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		logger.Logger.Error(
			"Getrlimit(RLIMIT_NOFILE) error",
			zap.Error(err),
		)
	} else {
		logger.Logger.Info(
			"Resource limits",
			zap.Uint64("rlimit_nofile_soft", rlimit.Cur),
			zap.Uint64("rlimit_nofile_hard", rlimit.Max),
			zap.String("gomemlimit", os.Getenv("GOMEMLIMIT")),
		)
	}
}

func initViper() error {
	// Imports config file values from least to most specific.
	viper.SetConfigName("config.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/config")  // /config/config.yaml
	viper.AddConfigPath("./config") // ./config/config.yaml
	viper.AddConfigPath(".")        // ./config.yaml

	// Setup Viper to also look at environment variables.
	viper.SetEnvPrefix(ApplicationNamespace)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // fix for nested struct references https://github.com/spf13/viper/issues/160#issuecomment-189551355
	viper.AutomaticEnv()

	// Enable environment variables to be unmarshalled to slices (https://stackoverflow.com/a/43241844).
	viper.SetTypeByDefaultValue(true)

	// Set defaults for all values in-order to use env config for all options.
	viper.SetDefault("server.webserverPort", 8080)
	viper.SetDefault("server.monitoringPort", 8081)
	viper.SetDefault("server.readTimeout", 30*time.Second)
	viper.SetDefault("server.idleTimeout", 30*time.Second)
	viper.SetDefault("server.disableKeepalive", false)
	viper.SetDefault("server.requestTimeout", 30*time.Second)
	viper.SetDefault("server.livezTimeout", 500*time.Millisecond)
	viper.SetDefault("server.readyzTimeout", 500*time.Millisecond)
	viper.SetDefault("server.rememberBusyTimeout", 5*time.Second)
	viper.SetDefault("server.metricsTimeout", 8*time.Second)
	viper.SetDefault("linter.maxQueueSize", 8192)
	viper.SetDefault("linter.badkeys.numProcesses", 1)
	viper.SetDefault("linter.badkeys.pythonDir", "autodetect")
	viper.SetDefault("linter.certlint.numProcesses", 1)
	viper.SetDefault("linter.certlint.rubyDir", "autodetect")
	viper.SetDefault("linter.dwklint.numGoroutines", 1)
	viper.SetDefault("linter.dwklint.blocklistDir", "autodetect")
	viper.SetDefault("linter.ftfy.numProcesses", 1)
	viper.SetDefault("linter.ftfy.pythonDir", "autodetect")
	viper.SetDefault("linter.pkilint.numProcesses", 1)
	viper.SetDefault("linter.pkilint.pythonDir", "autodetect")
	viper.SetDefault("linter.rocacheck.numGoroutines", 1)
	viper.SetDefault("linter.x509lint.numGoroutines", 1)
	viper.SetDefault("linter.zlint.numGoroutines", 1)
	viper.SetDefault("response.defaultFormat", "json")
	viper.SetDefault("response.jsonPrettyPrint", false)
	viper.SetDefault("logging.isDevelopment", false)
	viper.SetDefault("logging.level", "")
	viper.SetDefault("logging.samplingInitial", math.MaxInt)    // When both of these are set to MaxInt, sampling is disabled.
	viper.SetDefault("logging.samplingThereafter", math.MaxInt) // See https://pkg.go.dev/go.uber.org/zap/zapcore#NewSamplerWithOptions for more information.

	// Render results to Config Struct.
	_ = viper.ReadInConfig() // Ignore errors, because we also support reading config from environment variables.
	return viper.Unmarshal(&Config)
}

func ParseResponseFormat(format string) ResponseFormat {
	switch strings.ToLower(format) {
	case "html":
		return RESPONSEFORMAT_HTML
	case "json":
		return RESPONSEFORMAT_JSON
	case "text":
		return RESPONSEFORMAT_TEXT
	default:
		return -1
	}
}
