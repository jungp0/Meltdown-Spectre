# Meltdown and Spectre: Exploitations of the modern microprocessor design

<p style="text-align:center;">
<img src="https://meltdownattack.com/meltdown.png" height = 100px style="padding-right: 100px; padding left: 100px;">

<img src="https://meltdownattack.com/spectre.png" height = 100px style="padding-right: 100px; padding left: 100px;">
</p>

## Background 

Before 2017, nobody realized the modern microprocessor design exposed almost entire computer world in a severe vulnerability for decades.

The modern microprocessor architecture can be traced back to the late 1950s.[1] The IBM Stretch was an amazing design that introduced [branch predication](https://en.wikipedia.org/wiki/Branch_predictor), branch misprediction recovery, and precise interrupts. The design improved efficiency of processors and reduced transistor count by preprocessing the instruction stream to handle branches and memory loads as early as possible. However, the new features brought in fatal vulnerabilities.  

In 2015, an article pointed out the possibility of cache attack on mobile devices.[2] The targets are ARM-based, but it laid the groundwork for the attack vector.

On 3 January 2018, the public firstly got to know the existence of the vulnerabilities of microprocessors that attackers can steal processed data without privilege.[3] **All Intel x86 microprocessors, IBM POWER processors, and some ARM-based microprocessors were affected.** The vulnerabilities crossed platforms and operating systems, including IOS, Linux, macOS, and Windows. The vulnerabilities melted down not only the security boundaries, but also the security confidence.

***

## Who are they 

[**Meltdown**](https://en.wikipedia.org/wiki/Meltdown_(security_vulnerability))([CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754)) and [**Spectre**](https://en.wikipedia.org/wiki/Spectre_(security_vulnerability))([CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753)) allow programs to steal data which is currently processed on the computer. While programs are typically not permitted to read data from other programs, a malicious program can exploit Meltdown and Spectre to get hold of secrets stored in the memory of other running programs. This might include passwords stored in a password manager or browser, personal photos, emails, instant messages and even business-critical documents.

Spectre can be exploited remotely by code hosted on remote malicious web pages in JavaScript.The malware would have access to all the memory mapped to the address space of the running browser.

***

## How do they work

***Spectre opens your door for Meltdown***

We should talk about [instruction pipelining](https://en.wikipedia.org/wiki/Instruction_pipelining) firstly, which is used for instruction parallelism in a single processor. 

Here is an example from Wikipida[4] to help you quickly understand the basic concept:
<p>
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/c/cb/Pipeline%2C_4_stage.svg/1280px-Pipeline%2C_4_stage.svg.png" width = 500px>
</p>

<table>
<tbody><tr>
<th style="text-align:center;">Clock</th>
<th style="text-align:center;">Execution</th></tr>
<tr>
<td>0
</td>
<td>
<ul><li>Four instructions are waiting to be executed</li></ul>
</td></tr>
<tr>
<td>1
</td>
<td>
<ul><li>The green instruction is fetched from memory</li></ul>
</td></tr>
<tr>
<td>2
</td>
<td>
<ul><li>The green instruction is decoded</li>
<li>The purple instruction is fetched from memory</li></ul>
</td></tr>
<tr>
<td>3
</td>
<td>
<ul><li>The green instruction is executed (actual operation is performed)</li>
<li>The purple instruction is decoded</li>
<li>The blue instruction is fetched</li></ul>
</td></tr>
<tr>
<td>4
</td>
<td>
<ul><li>The green instruction's results are written back to the register file or memory</li>
<li>The purple instruction is executed</li>
<li>The blue instruction is decoded</li>
<li>The red instruction is fetched</li></ul>
</td></tr>
<tr>
<td>5
</td>
<td>
<ul><li>The execution of green instruction is completed</li>
<li>The purple instruction is written back</li>
<li>The blue instruction is executed</li>
<li>The red instruction is decoded</li></ul>
</td></tr>
<tr>
<td>6
</td>
<td>
<ul><li>The execution of purple instruction is completed</li>
<li>The blue instruction is written back</li>
<li>The red instruction is executed</li></ul>
</td></tr>
<tr>
<td>7
</td>
<td>
<ul><li>The execution of blue instruction is completed</li>
<li>The red instruction is written back</li></ul>
</td></tr>
<tr>
<td>8
</td>
<td>
<ul><li>The execution of red instruction is completed</li></ul>
</td></tr>
<tr>
<td>9
</td>
<td>
<ul><li>The execution of all four instructions is completed</li></ul>
</td></tr></tbody></table>

<br></br>

In real practices, instructions have different executing time. 

<p>
<img src="https://github.com/jungp0/Meltdown-Spectre/blob/main/Figures/2.jpg?raw=true">
</p>

Just take the instruction 1 and instruction 2 as an example. In sequential instruction execution, the instruction 2 needs the result of instruction 1, and they may follow a logical relationship. If the instruction 1 takes tons of time to execute, instruction 2 has to wait it. Another pipeline may be halting and all later instructions need to wait as well. 

<p>
<img src="https://github.com/jungp0/Meltdown-Spectre/blob/main/Figures/3.jpg?raw=true">
</p>

The branch prediction eliminates the waiting time. Branch Predictor will forecast the return of instruction 1, and execute instruction 2 with the predicted value in the pipeline. In this case, all instructions can be run parallel. 

The result of instruction 2 will be stored in re-order buffer(ROB). When the instruction 1 is completed, the return will be compared with predicted one. If the prediction is correct, processor will take the result from ROB and keep going on. If not, instruction 2 will be re-executed and **the previous track will be removed**.[5]

<p>
<img src="https://github.com/jungp0/Meltdown-Spectre/blob/main/Figures/4.jpg?raw=true">
</p>

You may have found out the vulnerabilities.

1. the instruction 2 can run without the result of instruction 1

2. if the branch prediction is wrong, the track of instruction 2 will be totally removed

## What does it mean

At the architectural level documented in processor data books, any results of misprediction are specified to be discarded after the fact, the resulting speculative execution may still leave around side effects, like loaded cache lines. 

Spectre can abuse the branch prediction simply by an "if-then" function. Malicious program can "train" processor to predict an intended value of the if statement, then read cache by misleading. Processor will be fooled, load the cache, have cache read, discard the "wrong" instruction, and **even forget it has loaded the cache**. Therefore, Spectre attack is hard to detect.

It is not the end, Meltdown is a perfect match.

Meltdown relies on a CPU race condition that can arise between instruction execution and privilege checking. Briefly speaking, the instruction execution leaves side effects that constitute information not hidden to the process by the privilege check. The process carrying out Meltdown then uses these side effects to infer the values of memory mapped data, bypassing the privilege check.[6]

Although Meltdown can only read memory in one instruction per attack, it can still read at high speed. Every address of interest, and depending on other running processes, the result may contain passwords, encryption data, and any other sensitive information, from any address of any process that exists in the memory map. 

*Check Paper about [Meltdown](https://meltdownattack.com/meltdown.pdf) and [Spectre](https://spectreattack.com/spectre.pdf)*

## Mitigation

Linux, macOS, IOS and Windows all released patches to mitigate the impacts. However, the architecture-level solution has not be announced. 

Microsoft provided solutions as below:

<table>
<caption>Summary of mitigation on Microsoft Windows [5]</caption>
<tbody><tr>
<th>Vulnerability</th>
<th>CVE</th>
<th>Exploit name</th>
<th>Public vulnerability name</th>
<th>Windows changes</th>
<th>Firmware changes
</th></tr>
<tr>
<td>(Spectre)</td>
<td>2017-5753</td>
<td>Variant 1</td>
<td>Bounds Check Bypass (BCB)</td>
<td>Recompiling with a new compiler<br>Hardened Browser to prevent exploit from JavaScript</td>
<td>No
</td></tr>
<tr>
<td>(Spectre)</td>
<td>2017-5715</td>
<td>Variant 2</td>
<td>Branch Target Injection (BTI)</td>
<td>New CPU instructions eliminating branch speculation</td>
<td>Yes
</td></tr>
<tr>
<td>Meltdown</td>
<td>2017-5754</td>
<td>Variant 3</td>
<td>Rogue Data Cache Load (RDCL)</td>
<td><a href="https://en.wikipedia.org/wiki/Kernel_page-table_isolation" title="Kernel page-table isolation">Isolate kernel and user mode page tables</a></td>
<td>No
</td></tr></tbody></table>

***

## Meltdown in action

- **[Proof-of-concept demo](https://github.com/IAIK/meltdown)**

    Clone the git repository from [meltdownattack](https://github.com/IAIK/meltdown):

    ```git clone https://github.com/IAIK/meltdown.git```

    Make the .c files:

    ```make```

    *The repository contains 5 demos of meltdown exploitation:*

1. Read accessible addresses from the own address space

    ```taskset 0x1 ./test```

2. Breaking Kernel Address Space Layout Randomizaton(KASLR)

    ```sudo taskset 0x1 ./kaslr```

3. Read reliable physical memory by physical map offset

    ```sudo taskset 0x1 ./reliability 0xffff880000000000```

4. Read physical memory from a different process

    ```sudo ./secret```

5. Dump the memory

    ```./memory_filler 9```

<br></br>

- **Examples**

[![IMAGE ALT TEXT](http://img.youtube.com/vi/bReA1dvGJ6Y/0.jpg)](http://www.youtube.com/watch?bReA1dvGJ6Y "Meltdown in Action: Dumping memory")

[![IMAGE ALT TEXT](http://img.youtube.com/vi/RbHbFkh6eeE/0.jpg)](http://www.youtube.com/watch?RbHbFkh6eeE "Meltdown demo - Spying on passwords")

<figure class="video_container">
  <iframe src="https://www.youtube.com/embed/RbHbFkh6eeE" frameborder="0" allowfullscreen="true"> </iframe>
</figure>

<figure class="video_container">
  <iframe src="https://www.youtube.com/embed/bReA1dvGJ6Y" frameborder="0" allowfullscreen="true"> </iframe>
</figure>

## References
[1] M. Smotherman, “IBM Stretch (7030) -- Aggressive Uniprocessor Parallelism,” Organization Sketch of IBM Stretch. [Online]. Available: https://people.cs.clemson.edu/~mark/stretch.html. [Accessed: 27-Mar-2021]. 

[2]	M. Lipp, D. Gruss, R. Spreitzer, C. Maurice, and S. Mangard, “ARMageddon: Cache attacks on mobile devices,” arXiv [cs.CR], 2015.

[3]	S. Gibbs, “Meltdown and Spectre: ‘worst ever’ CPU bugs affect virtually all computers,” The guardian, The Guardian, 04-Jan-2018.

[4]	Wikipedia contributors, “Instruction pipelining,” Wikipedia, The Free Encyclopedia, 08-Jan-2021. [Online]. Available: https://en.wikipedia.org/w/index.php?title=Instruction_pipelining&oldid=999049469. [Accessed: 27-Mar-2021].

[5]	P. Kocher et al., “Spectre attacks: Exploiting speculative execution,” arXiv [cs.CR], 2018.

[6]	M. Lipp et al., “Meltdown: Reading kernel memory from user space,” Commun. ACM, vol. 63, no. 6, pp. 46–56, 2020.

[7]	T. Myerson, “Understanding the performance impact of Spectre and Meltdown mitigations on Windows Systems,” Microsoft.com, 09-Jan-2018. [Online]. Available: https://www.microsoft.com/security/blog/2018/01/09/understanding-the-performance-impact-of-spectre-and-meltdown-mitigations-on-windows-systems/. [Accessed: 27-Mar-2021].

