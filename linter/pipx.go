package linter

import (
	"bufio"
	"fmt"
	"os/exec"

	"github.com/pkimetal/pkimetal/logger"

	"go.uber.org/zap"
)

var pipxLocalVenvsDir string

func getLocalVenvsDir() {
	// Get the pipx virtual environment path from the output of "pipx environment".
	cmd := exec.Command("pipx", "environment", "-V", "PIPX_LOCAL_VENVS")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Logger.Error("cmd.StdoutPipe() failed", zap.Error(err))
	} else if err = cmd.Start(); err != nil {
		logger.Logger.Error("cmd.Start() failed", zap.Error(err))
	} else {
		stdin := bufio.NewScanner(stdout)
		if stdin.Scan() {
			_, _ = fmt.Sscanf(stdin.Text(), "%s", &pipxLocalVenvsDir)
		}
	}

	cmd.Wait()
}

func GetPackageDetailsFromPipx(packageName, directory string) (string, string) {
	// Extract the package version and determine the Python directory from the output of "pipx list".
	if pipxLocalVenvsDir == "" {
		getLocalVenvsDir()
	}
	packageVersion := NOT_INSTALLED
	cmd := exec.Command("pipx", "list")
	if stdout, err := cmd.StdoutPipe(); err != nil {
		logger.Logger.Error("cmd.StdoutPipe() failed", zap.Error(err))
	} else if err = cmd.Start(); err != nil {
		logger.Logger.Error("cmd.Start() failed", zap.Error(err))
	} else {
		stdin := bufio.NewScanner(stdout)
		var version [3]int
		var pythonVersion [2]int
		for stdin.Scan() {
			n, _ := fmt.Sscanf(stdin.Text(), "   package "+packageName+" %d.%d.%d, installed using Python %d.%d", &version[0], &version[1], &version[2], &pythonVersion[0], &pythonVersion[1])
			if n >= 5 {
				packageVersion = fmt.Sprintf("%d.%d.%d", version[0], version[1], version[2])
				if directory == "autodetect" {
					directory = fmt.Sprintf("%s/%s/lib/python%d.%d/site-packages/", pipxLocalVenvsDir, packageName, pythonVersion[0], pythonVersion[1])
				}
				break
			}
		}
	}

	cmd.Wait()
	return packageVersion, directory
}
