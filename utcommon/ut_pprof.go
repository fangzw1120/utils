package utcommon

import (
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
)

// MyPprof ...
// @Description:
//
type MyPprof struct {
	cpuProfileFile *os.File
}

// SigPProf ...
const SigPProf = syscall.Signal(0x30)

// RunPprof kill -48 PID to start and end pprof
// @Description:
//
func RunPprof() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM, SigPProf)
	//log.Infof("wait for Signal(-48) to run pprof")

	var myPprof *MyPprof
	for {
		v := <-signals
		//log.Infof("%+v", v)
		switch v {
		case SigPProf:
			if myPprof == nil {
				myPprof = &MyPprof{}
				myPprof.StartCpuProfile()
			} else {
				myPprof.StopCpuProfile()
				myPprof.HeapProfile()
				myPprof = nil
			}
		default:
			//log.Infof("Got unregistered signal: %v", v)
		}
	}
}

// StartCpuProfile start cpu pprof
// @Description:
// @receiver m
// @return error
//
func (m *MyPprof) StartCpuProfile() error {
	f, err := os.OpenFile("cpu.prof", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		//log.Debugf("openfile err: %v", err)
		return err
	}
	m.cpuProfileFile = f
	//log.Debugf("CPU Profile started")
	err = pprof.StartCPUProfile(m.cpuProfileFile)
	if err != nil {
		//log.Debugf("start cpu profile err: %v", err)
	}
	return err
}

// StopCpuProfile stop cpu pprof
// @Description:
// @receiver m
// @return error
//
func (m *MyPprof) StopCpuProfile() error {
	pprof.StopCPUProfile()

	if m.cpuProfileFile != nil {
		m.cpuProfileFile.Close()
		m.cpuProfileFile = nil
	}
	//log.Debugf("CPU Profile stop")
	return nil
}

// HeapProfile memory pprof
// @Description:
// @receiver m
// @return error
//
func (m *MyPprof) HeapProfile() error {
	f, err := os.OpenFile("heap.prof", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		//log.Debugf("OpenFile err: %v", err)
		return err
	}
	defer f.Close()
	err = pprof.WriteHeapProfile(f)
	if err != nil {
		//log.Debugf("WriterHeapProfile err: %v", err)
		return err
	}
	return nil
}
