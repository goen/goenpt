package main

import (
	"bufio"
	"fmt"
	"os"
)

func sysfun2int(s []byte) uint16 {
	//	fmt.Println(">>",s,"<<")
	switch string(s) {
	case "execve":
		return 59
	case "wait4":
		return 61
	case "clone":
		return 56
	case "rt_sigreturn":
		return 15
	case "arch_prctl":
		return 158
	case "exit_group":
		return 231
	case "rt_sigaction":
		return 13
	case "rt_sigprocmask":
		return 14
	case "sigaltstack":
		return 131
	case "vfork":
		return 58
	default:
		return 0
	}
}

func syssig2int(s []byte) uint8 {
	//	fmt.Println(">>",string(s),"<<")
	switch string(s) {
	case "SIGABRT":
		return 6
	case "SIGALRM":
		return 14
	case "SIGFPE":
		return 8
	case "SIGHUP":
		return 1
	case "SIGILL":
		return 4
	case "SIGINT":
		return 2
	case "SIGKILL":
		return 9
	case "SIGPIPE":
		return 13
	case "SIGQUIT":
		return 3
	case "SIGSEGV":
		return 11
	case "SIGTERM":
		return 15
	case "SIGTTOU":
		return 22
	case "SIGTSTP":
		return 20
	case "SIGCONT":
		return 18
	case "SIGSTOP":
		return 19
	case "SIGCHLD":
		return 17
	case "SIGUSR2":
		return 31
	case "SIGUSR1":
		return 30
	case "SIGBUS":
		return 101
	case "SIGINFO":
		return 102
	case "SIGIO":
		return 103
	case "SIGNALED":
		return 104
	case "SIGPROF":
		return 105
	case "SIGPWR":
		return 106
	case "SIGRT":
		return 107
	case "SIGRTMIN":
		return 108
	case "SIGSTKFLT":
		return 109
	case "SIGSYS":
		return 110
	case "SIGTRAP":
		return 111
	case "SIGTTIN":
		return 112
	case "SIGURG":
		return 113
	case "SIGUSR":
		return 114
	case "SIGVTALRM":
		return 115
	case "SIGWINCH":
		return 116
	case "SIGXCPU":
		return 117
	case "SIGXFSZ":
		return 118
	default:
		return 0
	}
}

type fun struct {
	tid        uint32 //thread specific id
	sysfun     uint16 // platform specific syscall id
	reterr     int64  // return error code /child's tid
	sig        uint8
	sec        uint64
	nsec       uint32
	unfinished bool //beginning
	resumed    bool //end
	signal     bool
	xargs []string //exec & args
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

func parse(s []byte) (f fun) {

	seek0(&s, 10)

	//	fmt.Println("TOTAL=",string(s))

	if len(s) >= 1 && s[0] == '[' {

		//pid done
		fmt.Sscanf(string(s), "[pid%d]", &f.tid)

		for f.tid != 0 && seek1(&s) {
		}

	} else {
		//pid done
		fmt.Sscanf(string(s), "%d ", &f.tid)

		seek2(&s, ' ')
	}

	//time done
	fmt.Sscanf(string(s), "%d.%d", &f.sec, &f.nsec)

	seek2(&s, ' ')

	if len(s) == 0 {
		return
	}

	//	fmt.Println("||pid ts tn", f.tid, f.sec, f.nsec)

	var sysfunstr []byte
	var sysretstr []byte
	var syssig []byte
	var sysattr []byte
	switch s[0] {
	case '+':
		//exited done
		fmt.Sscanf(string(s), "+++ exited with %d +++", &f.reterr)
		f.sysfun = 1 //exit
		return
	case '-':
		f.signal = true

		seek2(&s, '-')
		seek2(&s, ' ')
		syssig = seek3(&s, ' ')
		f.sig = syssig2int(syssig)

		// FIXME: handle the signal type & child
		//		fmt.Println("FIXME SIGNAL:",string(s))
		return
	case '<':
		fmt.Sscanf(string(s), "<... %s resumed>", &sysfunstr)
		f.sysfun = sysfun2int(sysfunstr)
		f.resumed = true
		seek2(&s, ' ')
		seek2(&s, ' ')
		seek2(&s, ' ')

	default:
		sysfunstr = seek3(&s, '(')
		f.sysfun = sysfun2int(sysfunstr)

		if len(s) >= 1 && s[len(s)-1] == '>' {
			f.unfinished = true
			//			fmt.Println("unfinished???")
			seek4(&s, '<')
			seek0(&s, '<')
			seek0(&s, ' ')
		}
	}

	sysretstr = seek4(&s, ' ')
	fmt.Sscanf(string(sysretstr), "%d", &f.reterr)

	if f.sysfun == 13 && len(s) >= 10 {
		syssig = s[:10]
		seek2(&syssig, '(')
		seek4(&syssig, ',')
		if len(syssig) >= 1 {
			syssig = syssig[:len(syssig)-1]
			f.sig = syssig2int(syssig)
		}
		return
	}

	if f.sysfun == 59 {
		for {
			sysattr = seek5(&s)
			seek5(&s)
			if len(sysattr) == 0 {
				break
			}
			f.xargs = append(f.xargs, string(sysattr))
		}
	}

	// FIXME: handle the arguments
	//fmt.Println("FIXME RESUMED /PID",f.tid,"/ /",f.sysfun,"/ (",f.reterr,"):",string(s))

	//	fmt.Println("FIXME NORMAL sig=",f.sig," /",f.sysfun,"/ (",f.reterr,"):",string(s))

	//	if f.sysfun == 0 {die()}

	return f
}

func main() {
	//	q := strings.NewReader(input)
	q, _ := os.Open("test/kernelmake.pid")
	r := bufio.NewReader(q)

	for {
		l, err := r.ReadString('\n')
		f := parse([]byte(l))

		_ = f

		if err != nil {
			break
		}
	}
}
