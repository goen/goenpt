package main

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func Sysfun2int(s []byte) uint16 {
	//	fmt.Println(">>",s,"<<")
	switch string(s) {
	case "execve":
		return 59
	case "wait4":
		return 61
	case "clone":
		return 56
	case "rt_Sigreturn":
		return 15
	case "arch_prctl":
		return 158
	case "exit_group":
		return 231
	case "rt_Sigaction":
		return 13
	case "rt_Sigprocmask":
		return 14
	case "Sigaltstack":
		return 131
	case "vfork":
		return 58
	default:
		return 0
	}
}

func sysSig2int(s []byte) uint8 {
	//	fmt.Println(">>",string(s),"<<")
	switch string(s) {
	case "SigABRT":
		return 6
	case "SigALRM":
		return 14
	case "SigFPE":
		return 8
	case "SigHUP":
		return 1
	case "SigILL":
		return 4
	case "SigINT":
		return 2
	case "SigKILL":
		return 9
	case "SigPIPE":
		return 13
	case "SigQUIT":
		return 3
	case "SigSEGV":
		return 11
	case "SigTERM":
		return 15
	case "SigTTOU":
		return 22
	case "SigTSTP":
		return 20
	case "SigCONT":
		return 18
	case "SigSTOP":
		return 19
	case "SigCHLD":
		return 17
	case "SigUSR2":
		return 31
	case "SigUSR1":
		return 30
	case "SigBUS":
		return 101
	case "SigINFO":
		return 102
	case "SigIO":
		return 103
	case "SignalED":
		return 104
	case "SigPROF":
		return 105
	case "SigPWR":
		return 106
	case "SigRT":
		return 107
	case "SigRTMIN":
		return 108
	case "SigSTKFLT":
		return 109
	case "SigSYS":
		return 110
	case "SigTRAP":
		return 111
	case "SigTTIN":
		return 112
	case "SigURG":
		return 113
	case "SigUSR":
		return 114
	case "SigVTALRM":
		return 115
	case "SigWINCH":
		return 116
	case "SigXCPU":
		return 117
	case "SigXFSZ":
		return 118
	default:
		return 0
	}
}

type Fun struct {
	Tid        uint32 //thread specific id
	Sysfun     uint16 // platform specific syscall id
	Reterr     int64  // return error code /child's Tid
	Sig        uint8
	Sec        uint64
	NSec       uint32
	Unfinished bool //beginning
	Resumed    bool //end
	Signal     bool
	Xargs      []string //exec & args
}

func fromHexChar(c byte) (byte, byte) {
	switch {
	case c == '\\':
		return 0, 1
	case c == 'x':
		return 0, 1
	case '0' <= c && c <= '9':
		return c - '0', 0
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, 0
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, 0
	}

	return 0, 2
}

func seek1(s *[]byte) bool {
	if len(*s) >= 2 {
		if (*s)[0] != ']' {
			*s = (*s)[1:]
		} else {
			*s = (*s)[2:]
			return false
		}
	}
	return true
}

func seek2(s *[]byte, c byte) {
	for len(*s) >= 1 && (*s)[0] != c {
		*s = (*s)[1:]
	}
	for len(*s) >= 1 && (*s)[0] == c {
		*s = (*s)[1:]
	}
}

func seek3(s *[]byte, c byte) (o []byte) {
	for len(*s) >= 1 && (*s)[0] != c {
		o = append(o, (*s)[0])
		*s = (*s)[1:]
	}
	return o
}

func seek0(s *[]byte, c byte) {
	if len(*s) >= 1 && (*s)[len(*s)-1] == c {
		*s = (*s)[:len(*s)-1]
	}
}

func seek4(s *[]byte, c byte) (o []byte) {
	for len(*s) >= 1 && (*s)[len(*s)-1] != c {
		o = append(o, (*s)[len(*s)-1])
		*s = (*s)[:len(*s)-1]
	}

	for j := range o {
		i := len(o) - j - 1
		if i <= j {
			break
		}
		t := o[j]
		o[j] = o[i]
		o[i] = t
	}

	return o
}

func seek5(s *[]byte) (o []byte) {
	ee := 0
	var dd byte = 0
	var cc byte = 0
	for len(*s) >= 1 {
		if '"' == (*s)[0] {
			ee++
			if ee == 2 {
				if cc != 0 {
					o = append(o, cc)
				}
				break
			}
		}
		aa, bb := fromHexChar((*s)[0])
		if bb == 3 {
			return o
		} else if bb == 0 {
			cc *= 16
			cc += aa
		} else {
			if cc != 0 {
				dd = cc
				cc = 0
			} else if dd != 0 {
				o = append(o, dd)
				dd = 0
			}
		}

		(*s) = (*s)[1:]
	}
	return o
}

func parse(s []byte) (f Fun) {

	seek0(&s, 10)

	//	fmt.Println("TOTAL=",string(s))

	if len(s) >= 1 && s[0] == '[' {

		//pid done
		fmt.Sscanf(string(s), "[pid%d]", &f.Tid)

		for f.Tid != 0 && seek1(&s) {
		}

	} else {
		//pid done
		fmt.Sscanf(string(s), "%d ", &f.Tid)

		seek2(&s, ' ')
	}

	//time done
	fmt.Sscanf(string(s), "%d.%d", &f.Sec, &f.NSec)

	seek2(&s, ' ')

	if len(s) == 0 {
		return
	}

	//	fmt.Println("||pid ts tn", f.Tid, f.Sec, f.NSec)

	var Sysfunstr []byte
	var sysretstr []byte
	var sysSig []byte
	var sysattr []byte
	switch s[0] {
	case '+':
		//exited done
		fmt.Sscanf(string(s), "+++ exited with %d +++", &f.Reterr)
		f.Sysfun = 1 //exit
		return
	case '-':
		f.Signal = true

		seek2(&s, '-')
		seek2(&s, ' ')
		sysSig = seek3(&s, ' ')
		f.Sig = sysSig2int(sysSig)

		// FIXME: handle the Signal type & child
		//		fmt.Println("FIXME Signal:",string(s))
		return
	case '<':
		fmt.Sscanf(string(s), "<... %s Resumed>", &Sysfunstr)
		f.Sysfun = Sysfun2int(Sysfunstr)
		f.Resumed = true
		seek2(&s, ' ')
		seek2(&s, ' ')
		seek2(&s, ' ')

	default:
		Sysfunstr = seek3(&s, '(')
		f.Sysfun = Sysfun2int(Sysfunstr)

		if len(s) >= 1 && s[len(s)-1] == '>' {
			f.Unfinished = true
			//			fmt.Println("Unfinished???")
			seek4(&s, '<')
			seek0(&s, '<')
			seek0(&s, ' ')
		}
	}

	sysretstr = seek4(&s, ' ')
	fmt.Sscanf(string(sysretstr), "%d", &f.Reterr)

	if f.Sysfun == 13 && len(s) >= 10 {
		sysSig = s[:10]
		seek2(&sysSig, '(')
		seek4(&sysSig, ',')
		if len(sysSig) >= 1 {
			sysSig = sysSig[:len(sysSig)-1]
			f.Sig = sysSig2int(sysSig)
		}
		return
	}

	if f.Sysfun == 59 {
		for {
			sysattr = seek5(&s)
			seek5(&s)
			if len(sysattr) == 0 {
				break
			}
			f.Xargs = append(f.Xargs, string(sysattr))
		}
	}

	// FIXME: handle the arguments
	//fmt.Println("FIXME Resumed /PID",f.Tid,"/ /",f.Sysfun,"/ (",f.Reterr,"):",string(s))

	//	fmt.Println("FIXME NORMAL Sig=",f.Sig," /",f.Sysfun,"/ (",f.Reterr,"):",string(s))

	//	if f.Sysfun == 0 {die()}

	return f
}

func getgbin() (s string, e error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("No current wd")
	}
	for {
		wd = filepath.Dir(wd)
		s = wd + "/" + mpoint_gbin
		//				fmt.Println(s)
		_, err := os.Stat(s)
		if err == nil {
			return s, nil
		}
		if "/" == wd {
			break
		}
	}
	return "", fmt.Errorf("goen dir not found")
}

func main() {

	arg := []string{"-ttt", "-xx", "-q", "-f", "-e", "trace=process,signal,ipc"}
	for y := range os.Args[1:] {
		arg = append(arg, os.Args[y+1])
	}
	_ = arg

	//	fmt.Println("strace:", arg)
		cmd := exec.Command("strace", arg...)
	//	cmd := exec.Command("strace", "-ttt", "-xx", "-q", "-f", "-e", "trace=process,signal,ipc","go","build")
	//	cmd := exec.Command("cat", "test/kernelmake.pid")

	stdout, er3 := cmd.StderrPipe()
	if er3 != nil {
		fmt.Println(er3)
		return

	}

	//	go stracer(&rtrace, &stop, &stopl)

	gb, er4 := getgbin()
	if er4 != nil {
		fmt.Println(er4)
		return
	}

	fmt.Println("Waiting for the pipeline")

	//	s, errr := os.Open(gb+"/trace")
	s, errr := os.OpenFile(gb+"/trace", os.O_WRONLY, 0200)
	if errr != nil {
		fmt.Println(errr)
		return
	}
	defer s.Close()

	// now run strace
	er6 := cmd.Start()
	if er6 != nil {
		fmt.Println(er6)
		return
	}

	// read command's stdout line by line
	in := bufio.NewScanner(stdout)

	t := bufio.NewWriter(s)
	enc := gob.NewEncoder(t)
	_ = enc
	//	r := bufio.NewReader(rtrace)

	fmt.Println("going")

	for {
		if !in.Scan() {
			t.Flush()
			break
		}

		l := in.Text()
//		fmt.Println(l)
		f := parse([]byte(l))
		err := enc.Encode(f)
		if err != nil {
			fmt.Println("Pipe detach:", err)
			break
		}
	}
	if er9 := in.Err(); er9 != nil {
		fmt.Println("error:", er9)
	}

	er8 := cmd.Wait()
	if er8 != nil {
		fmt.Println("error:", er8)
	}

//	fmt.Println("gone")
//	time.Sleep(100000000)
}
