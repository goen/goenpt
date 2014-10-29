package main

import (
	"time"
	"strings"
	"bufio"
	"fmt"
	_"strconv"
)

func sysfun2int(s string) uint16 {
	fmt.Println(">>",s,"<<")
	switch(s) {
	case "execve": return 11
	case "wait4": return 114
	case "clone": return 120
	case "rt_sigreturn": return 173
	case "rt_sigreturn()": return 173
	default: return 0
	}
}

type fun struct {
	pid uint32 //process specific id
	tid uint32 //thread specific id
	sysfun uint16 // platform specific signal id/syscall id
	reterr int32		// return error code
	nsecdiff uint32	// nsec diff
	unfinished bool //beginning
	resumed bool //end
	signal bool
	exectra bool //is exectra
}

type context struct {
	mainpid uint32
	time.Time
}

type exectra struct {
	file string //exec file
	args []string //exec args
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

const (
	dumpres = true
)

func (p context) parse(s []byte) (f fun, e exectra) {
	fmt.Sscanf(string(s), "[pid%d]", &f.tid)

	for f.tid != 0 && seek1(&s) {}

	var ts,tn uint64
	fmt.Sscanf(string(s), "%d.%d", &ts, &tn)

	seek2(&s,' ')

	if len(s) == 0 {
		return
	}

	var sysfunstr string

	switch(s[0]) {
	case '+':
		fmt.Sscanf(string(s), "+++ exited with %d +++", &f.reterr)
		f.sysfun = 1 //exit
	return
	case '-':
		f.signal = true
		fmt.Println("FIXME SIGNAL:",string(s))
	return
	case '<':
		fmt.Sscanf(string(s), "<... %s resumed>", &sysfunstr)
		f.sysfun = sysfun2int(sysfunstr)
		f.resumed = true
		seek2(&s,' ')
		seek2(&s,' ')
		seek2(&s,' ')
		fmt.Println("FIXME RESUMED:",string(s))
	return
	default:
		fmt.Sscanf(string(s), "%s(", &sysfunstr)
		f.sysfun = sysfun2int(sysfunstr)
	}

	fmt.Println(string(s))

	return f,e
}

func main() {
	q := strings.NewReader(input)
	r := bufio.NewReader(q)

	var c context

	for {
		l, err := r.ReadString('\n')
		fmt.Println("****")
		f, e := c.parse([]byte(l))

		_ =f
		_=e

		if dumpres {
			fmt.Println(f,e)
		}

		if err != nil {
			break
		}
	}
}


var input = `1414528580.028840 execve("\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x31\x5f\x33\x5f\x33\x2f\x67\x6f\x2f\x62\x69\x6e\x2f\x67\x6f", ["\x67\x6f", "\x62\x75\x69\x6c\x64"], [/* 72 vars */]) = 0
1414528580.031500 arch_prctl(ARCH_SET_FS, 0x7fd0c90e5740) = 0
1414528580.032268 rt_sigaction(SIGRTMIN, {0x7fd0c8cd17e0, [], SA_RESTORER|SA_SIGINFO, 0x7fd0c8cdabb0}, NULL, 8) = 0
1414528580.032420 rt_sigaction(SIGRT_1, {0x7fd0c8cd1860, [], SA_RESTORER|SA_RESTART|SA_SIGINFO, 0x7fd0c8cdabb0}, NULL, 8) = 0
1414528580.032577 rt_sigprocmask(SIG_UNBLOCK, [RTMIN RT_1], NULL, 8) = 0
1414528580.034035 sigaltstack({ss_sp=0xc208006000, ss_flags=0, ss_size=32768}, NULL) = 0
1414528580.034219 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
1414528580.034340 rt_sigaction(SIGHUP, NULL, {SIG_DFL, [], 0}, 8) = 0
1414528580.034462 rt_sigaction(SIGHUP, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.034574 rt_sigaction(SIGINT, NULL, {SIG_DFL, [], 0}, 8) = 0
1414528580.034672 rt_sigaction(SIGINT, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.034775 rt_sigaction(SIGQUIT, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.034877 rt_sigaction(SIGILL, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.034978 rt_sigaction(SIGTRAP, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035078 rt_sigaction(SIGABRT, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035180 rt_sigaction(SIGBUS, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035282 rt_sigaction(SIGFPE, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035383 rt_sigaction(SIGUSR1, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035486 rt_sigaction(SIGSEGV, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035589 rt_sigaction(SIGUSR2, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035692 rt_sigaction(SIGPIPE, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035796 rt_sigaction(SIGALRM, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.035898 rt_sigaction(SIGTERM, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036000 rt_sigaction(SIGSTKFLT, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036101 rt_sigaction(SIGCHLD, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036202 rt_sigaction(SIGURG, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036306 rt_sigaction(SIGXCPU, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036409 rt_sigaction(SIGXFSZ, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036514 rt_sigaction(SIGVTALRM, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036615 rt_sigaction(SIGPROF, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036718 rt_sigaction(SIGWINCH, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036822 rt_sigaction(SIGIO, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.036922 rt_sigaction(SIGPWR, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037022 rt_sigaction(SIGSYS, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037124 rt_sigaction(SIGRT_2, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037228 rt_sigaction(SIGRT_3, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037330 rt_sigaction(SIGRT_4, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037432 rt_sigaction(SIGRT_5, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037534 rt_sigaction(SIGRT_6, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037636 rt_sigaction(SIGRT_7, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037739 rt_sigaction(SIGRT_8, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.037974 rt_sigaction(SIGRT_9, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.038162 rt_sigaction(SIGRT_10, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.038293 rt_sigaction(SIGRT_11, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.038418 rt_sigaction(SIGRT_12, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.038547 rt_sigaction(SIGRT_13, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.038905 rt_sigaction(SIGRT_14, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039052 rt_sigaction(SIGRT_15, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039190 rt_sigaction(SIGRT_16, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039295 rt_sigaction(SIGRT_17, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039397 rt_sigaction(SIGRT_18, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039497 rt_sigaction(SIGRT_19, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039597 rt_sigaction(SIGRT_20, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039698 rt_sigaction(SIGRT_21, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039796 rt_sigaction(SIGRT_22, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.039933 rt_sigaction(SIGRT_23, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040039 rt_sigaction(SIGRT_24, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040145 rt_sigaction(SIGRT_25, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040247 rt_sigaction(SIGRT_26, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040350 rt_sigaction(SIGRT_27, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040452 rt_sigaction(SIGRT_28, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040555 rt_sigaction(SIGRT_29, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040660 rt_sigaction(SIGRT_30, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040761 rt_sigaction(SIGRT_31, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.040862 rt_sigaction(SIGRT_32, {0x4874b0, ~[], SA_RESTORER|SA_STACK|SA_RESTART|SA_SIGINFO, 0x487520}, NULL, 8) = 0
1414528580.041300 rt_sigprocmask(SIG_SETMASK, ~[RTMIN RT_1], [], 8) = 0
1414528580.041574 clone(child_stack=0x7fd0c8901fb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fd0c89029d0, tls=0x7fd0c8902700, child_tidptr=0x7fd0c89029d0) = 5803
[pid  5802] 1414528580.041743 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5803] 1414528580.041883 sigaltstack({ss_sp=0xc20801a000, ss_flags=0, ss_size=32768}, NULL) = 0
[pid  5803] 1414528580.042029 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5803] 1414528580.046624 rt_sigprocmask(SIG_SETMASK, ~[RTMIN RT_1], [], 8) = 0
[pid  5803] 1414528580.046941 clone(child_stack=0x7fd0c3ffefb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fd0c3fff9d0, tls=0x7fd0c3fff700, child_tidptr=0x7fd0c3fff9d0) = 5804
[pid  5803] 1414528580.047173 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid  5804] 1414528580.047219 sigaltstack({ss_sp=0xc208064000, ss_flags=0, ss_size=32768} <unfinished ...>
[pid  5803] 1414528580.047258 <... rt_sigprocmask resumed> NULL, 8) = 0
[pid  5804] 1414528580.047286 <... sigaltstack resumed> , NULL) = 0
[pid  5804] 1414528580.047322 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5804] 1414528580.047747 rt_sigprocmask(SIG_SETMASK, ~[RTMIN RT_1], [], 8) = 0
[pid  5804] 1414528580.047996 clone(child_stack=0x7fd0c37fdfb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fd0c37fe9d0, tls=0x7fd0c37fe700, child_tidptr=0x7fd0c37fe9d0) = 5805
[pid  5804] 1414528580.048160 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid  5805] 1414528580.048218 sigaltstack({ss_sp=0xc20806c000, ss_flags=0, ss_size=32768} <unfinished ...>
[pid  5804] 1414528580.048264 <... rt_sigprocmask resumed> NULL, 8) = 0
[pid  5805] 1414528580.048297 <... sigaltstack resumed> , NULL) = 0
[pid  5805] 1414528580.048344 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5805] 1414528580.048641 rt_sigprocmask(SIG_SETMASK, ~[RTMIN RT_1], [], 8) = 0
[pid  5805] 1414528580.048835 clone(child_stack=0x7fd0c2ffcfb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fd0c2ffd9d0, tls=0x7fd0c2ffd700, child_tidptr=0x7fd0c2ffd9d0) = 5806
[pid  5805] 1414528580.048984 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid  5806] 1414528580.049039 sigaltstack({ss_sp=0xc208074000, ss_flags=0, ss_size=32768} <unfinished ...>
[pid  5805] 1414528580.049091 <... rt_sigprocmask resumed> NULL, 8) = 0
[pid  5806] 1414528580.049122 <... sigaltstack resumed> , NULL) = 0
[pid  5806] 1414528580.049163 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5802] 1414528580.054938 rt_sigprocmask(SIG_SETMASK, ~[RTMIN RT_1], [], 8) = 0
[pid  5802] 1414528580.055241 clone(child_stack=0x7fd0c27fbfb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fd0c27fc9d0, tls=0x7fd0c27fc700, child_tidptr=0x7fd0c27fc9d0) = 5807
[pid  5807] 1414528580.055490 sigaltstack({ss_sp=0xc2080ae000, ss_flags=0, ss_size=32768}, NULL) = 0
[pid  5802] 1414528580.055588 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid  5807] 1414528580.055660 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5802] 1414528580.055773 <... rt_sigprocmask resumed> NULL, 8) = 0
[pid  5802] 1414528580.060108 rt_sigprocmask(SIG_SETMASK, ~[RTMIN RT_1], [], 8) = 0
[pid  5802] 1414528580.060433 clone(child_stack=0x7fd0c1ffafb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fd0c1ffb9d0, tls=0x7fd0c1ffb700, child_tidptr=0x7fd0c1ffb9d0) = 5808
[pid  5802] 1414528580.060665 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5808] 1414528580.060796 sigaltstack({ss_sp=0xc2080b6000, ss_flags=0, ss_size=32768}, NULL) = 0
[pid  5808] 1414528580.060937 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid  5808] 1414528580.257596 clone(child_stack=0, flags=SIGCHLD) = 5809
[pid  5809] 1414528580.258383 execve("\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x31\x5f\x33\x5f\x33\x2f\x67\x6f\x2f\x70\x6b\x67\x2f\x74\x6f\x6f\x6c\x2f\x6c\x69\x6e\x75\x78\x5f\x61\x6d\x64\x36\x34\x2f\x36\x67", ["\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x31\x5f\x33\x5f\x33\x2f\x67"..., "\x2d\x6f", "\x2f\x74\x6d\x70\x2f\x67\x6f\x2d\x62\x75\x69\x6c\x64\x38\x38\x38\x36\x31\x30\x36\x30\x39\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63"..., "\x2d\x74\x72\x69\x6d\x70\x61\x74\x68", "\x2f\x74\x6d\x70\x2f\x67\x6f\x2d\x62\x75\x69\x6c\x64\x38\x38\x38\x36\x31\x30\x36\x30\x39", "\x2d\x70", "\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x2f\x72\x65\x70\x6f\x2e\x67\x69\x74\x2f\x67\x6f\x65\x6e\x66\x75\x73\x65", "\x2d\x63\x6f\x6d\x70\x6c\x65\x74\x65", "\x2d\x44", "\x5f\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x70\x61\x74\x68\x2f\x67"..., "\x2d\x49", "\x2f\x74\x6d\x70\x2f\x67\x6f\x2d\x62\x75\x69\x6c\x64\x38\x38\x38\x36\x31\x30\x36\x30\x39", "\x2d\x49", "\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x70\x61\x74\x68\x2f\x67\x6f"..., "\x2d\x70\x61\x63\x6b", "\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x70\x61\x74\x68\x2f\x67\x6f"..., ...], [/* 72 vars */]) = 0
[pid  5808] 1414528580.259503 wait4(5809,  <unfinished ...>
[pid  5809] 1414528580.261106 arch_prctl(ARCH_SET_FS, 0x7f06a7118740) = 0
[pid  5809] 1414528580.261863 rt_sigaction(SIGBUS, {0x425410, [BUS], SA_RESTORER|SA_RESTART, 0x7f06a6885ff0}, {SIG_DFL, [], 0}, 8) = 0
[pid  5809] 1414528580.262008 rt_sigaction(SIGSEGV, {0x425410, [SEGV], SA_RESTORER|SA_RESTART, 0x7f06a6885ff0}, {SIG_DFL, [], 0}, 8) = 0
[pid  5809] 1414528580.452969 exit_group(0) = ?
[pid  5809] 1414528580.457460 +++ exited with 0 +++
[pid  5808] 1414528580.457488 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, {ru_utime={0, 152439}, ru_stime={0, 35178}, ...}) = 5809
[pid  5808] 1414528580.457525 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=5809, si_status=0, si_utime=15, si_stime=3} ---
[pid  5808] 1414528580.457557 rt_sigreturn() = 5809
[pid  5808] 1414528580.457921 clone(child_stack=0, flags=SIGCHLD) = 5810
[pid  5810] 1414528580.458221 execve("\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x31\x5f\x33\x5f\x33\x2f\x67\x6f\x2f\x70\x6b\x67\x2f\x74\x6f\x6f\x6c\x2f\x6c\x69\x6e\x75\x78\x5f\x61\x6d\x64\x36\x34\x2f\x36\x6c", ["\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x31\x5f\x33\x5f\x33\x2f\x67"..., "\x2d\x6f", "\x2f\x74\x6d\x70\x2f\x67\x6f\x2d\x62\x75\x69\x6c\x64\x38\x38\x38\x36\x31\x30\x36\x30\x39\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63"..., "\x2d\x4c", "\x2f\x74\x6d\x70\x2f\x67\x6f\x2d\x62\x75\x69\x6c\x64\x38\x38\x38\x36\x31\x30\x36\x30\x39", "\x2d\x4c", "\x2f\x68\x6f\x6d\x65\x2f\x6d\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x47\x4f\x4c\x41\x4e\x47\x2f\x67\x6f\x70\x61\x74\x68\x2f\x67\x6f"..., "\x2d\x65\x78\x74\x6c\x64\x3d\x67\x63\x63", "\x2f\x74\x6d\x70\x2f\x67\x6f\x2d\x62\x75\x69\x6c\x64\x38\x38\x38\x36\x31\x30\x36\x30\x39\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63"...], [/* 72 vars */]) = 0
[pid  5808] 1414528580.458632 wait4(5810,  <unfinished ...>
[pid  5810] 1414528580.459197 arch_prctl(ARCH_SET_FS, 0x7f73a4ab0740) = 0
[pid  5810] 1414528580.942738 exit_group(0) = ?
[pid  5810] 1414528580.947793 +++ exited with 0 +++
[pid  5808] 1414528580.947821 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, {ru_utime={0, 346124}, ru_stime={0, 101801}, ...}) = 5810
[pid  5808] 1414528580.947854 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=5810, si_status=0, si_utime=34, si_stime=10} ---
[pid  5808] 1414528580.947893 rt_sigreturn() = 5810
[pid  5802] 1414528580.976532 exit_group(0) = ?
[pid  5807] 1414528580.976612 +++ exited with 0 +++
[pid  5808] 1414528580.976627 +++ exited with 0 +++
[pid  5806] 1414528580.976639 +++ exited with 0 +++
[pid  5805] 1414528580.976648 +++ exited with 0 +++
[pid  5804] 1414528580.976658 +++ exited with 0 +++
[pid  5803] 1414528580.976667 +++ exited with 0 +++
1414528580.977023 +++ exited with 0 +++
`
