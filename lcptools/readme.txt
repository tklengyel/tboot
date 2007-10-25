Introduction
	In order for Intel Trusted Execution Technology with Launch Control Policy (LCP) feature to work successfully, both 
    the Platform Supplier and the Platform Owner needs to be able to establish policy on the platform. In order to do this 
    a number of tools have to be provided to the eco-system:
	1) Enabling BIOS vendors and OS Vendors to publish measurement values for the respective components, 
	2) Allowing OEM's and IT shops to place these values into Policies which reside on their systems.

	The LCP Tools is such a tool provided by Intel to let Platform Supplier / Platform Owner/ BIOS Vendors to define the
    indices, create/release the policy and write policies on the TPM 1.2.

Build Requirements
	Linux Kernel Requirements:
	Linux Kernel: Version 2.6.17 or later, which should contain the 1.2 TPM drivers.
	Enhanced TSS Compiling Dependencies:
	Automake: Version 1.4 or later
	Autoconf:  Version 1.4 or later
	Pkgconfig
	Libtool 
	Gtk2-devel
	OpenSSL: Version 0.9.7 or later
	OpenSSL-Devel: Version 0.9.7 or later
	Pthreads library (glibc-devel)

Building LcpTools(Linux Version)
	1)	Extract source code into /LcpTool
	2)	Build Enhanced TSS:
		a.	Enter /LcpTool/Linux/Enhanced_TSS
		b.	Run sh bootstrap.sh to create makefile
		c.	Run ./configure to configure the Enhanced TSS.
		d.	Run make to build Enhanced TSS source code
		e.	Run make install to install Enhanced TSS into system
		  Sample:
		  $ cd Folder_of_Enhanced_TrouSerS
		  $ sh bootstrap.sh
		  $ ./configure [--enable-debug] [--enable-gprof] [--enable-gcov]
		  $ make
		  # make install
	3)	Build Lcp Tools:
		a.	Enter /LcpTool/LcpTools;
		b.	Run make to build LcpTools;
		c.	Run make install to install LcpTools to /usr/local/bin/;
		d.	Use dir /usr/local/bin/ to check the build results;

Run:
	1)	Load TPM Driver:
	Run "modprobe tpm_tis force=1 interrputs=0" to load TPM driver
	2)	Startup Enhanced_TSS stack:
	Run "tcsd" to start the daemon of Enhanced_TSS stack.
	3)	Run the commands of Lcp Tools

Warning
	The tools can only run on the machine with TPM 1.2 Device. And be careful on using the nvlock command, because after
    the tpm device is locked, it could not be unlocked again. 
