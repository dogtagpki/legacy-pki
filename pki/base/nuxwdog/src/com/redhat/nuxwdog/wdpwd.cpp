// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA
//
// Copyright (C) 2009 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>

static void echoOff(int fd)
{
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

static void echoOn(int fd)
{
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag |= ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

/* Routines to access named password strings */

typedef struct pwdenc_s pwdenc_t;
struct pwdenc_s {
    int len;
    void *ptr;
};

typedef struct pwddef_s pwddef_t;
struct pwddef_s {
    struct pwddef_s *pwdnext;
    char *pwdname;
    pwdenc_t pwdvalue;
    int serial;
};

static pwddef_t *pwdlist = 0;


/*
 * poor man's cipher block chaining encryption
 * this is NOT secure in any way, but still way better than storing
 * things in clear text.
 */
char *
wd_pwd_obscurify(char *src, char *dest, int len, int decrypt)
{
    unsigned char *res, *d, *s;
    unsigned char chain;
    // random bits to mask any symmetry and periods
    // got these from calling md5sum on the contents of some NIS maps
    // you cannot really call this a key, so:
    static unsigned char obscurificator[] =
        { 0x5e, 0xe5, 0x81, 0xeb, 0xd8, 0x55, 0x3f, 0x2c,
          0x92, 0xe8, 0xd2, 0xdd, 0x76, 0x48, 0xc2, 0x04, 
          0xc7, 0x5c, 0x00, 0xbf, 0x50, 0x5c, 0xbf, 0xf1,
          0xbd, 0x48, 0x21, 0x79, 0xe1, 0x17, 0xec, 0x63,
          0x5b, 0x6c, 0x05, 0xed, 0x5d, 0xc6, 0xc6, 0x1c,
          0xef, 0xc3, 0xe6, 0x12, 0xeb, 0xf9, 0x06, 0xc1,
          0x49, 0x83, 0xe6, 0x8d, 0x16, 0x23, 0x70, 0xa3,
          0x22, 0x21, 0x1e, 0x10, 0x6c, 0x8c, 0xda, 0xba };

    // allocate one byte more because we want to null-terminate the thing
    // when we're decypting
    if ((res = (unsigned char *)malloc(len + 1)) == NULL)
        return NULL;
    
    s = (unsigned char *)src;
    d = (unsigned char *)dest;
    chain = 0;                          /* initialization vector for CBC */
    while (len--) {
        /*
         * 11 must be relatively prime to sizeof(obscurificator),
         * if so, we're going to hit all the values from
         * 0 .. sizeof(obscurificator)
         */
        *d = *s ^ chain ^ obscurificator[(len * 11) % sizeof(obscurificator)];
        chain = (decrypt) ? *s : *d;    /* chain feedback - we always feed back ciphertext */
        s++; d++;
    }
    return (char *)res;
}

void
watchdog_pwd_encrypt(char *pwdvalue, pwdenc_t *pwdcrypt)
{
    if (pwdcrypt == NULL)
        return;

    memset((void *)pwdcrypt, 0, sizeof(pwdenc_t));

    if (!pwdvalue) {
        return;
    }

    int len = strlen(pwdvalue);
    {
        if ((pwdcrypt->ptr = (void *)malloc(len)) == NULL)
            return;
    
        pwdcrypt->len = len;
        wd_pwd_obscurify(pwdvalue, (char *)pwdcrypt->ptr, len, 0);
    }
}

char *
watchdog_pwd_decrypt(pwdenc_t *pwdcrypt)
{
    if (!pwdcrypt->ptr) {
	return NULL;
    }
    {
        char *buf;
        if ((buf = (char *)malloc(pwdcrypt->len + 1)) == NULL)
            return NULL;
        wd_pwd_obscurify((char *)(pwdcrypt->ptr), buf, pwdcrypt->len, 1);
        buf[pwdcrypt->len] = 0;   // null-terminate
        return buf;
    }
}

void
watchdog_pwd_free(pwdenc_t *pwdcrypt)
{
    if (pwdcrypt) {
        if (pwdcrypt->ptr) {
            memset(pwdcrypt->ptr, 0, pwdcrypt->len);
            free(pwdcrypt->ptr);
        }
        memset((void *)pwdcrypt, 0, sizeof(pwdenc_t));
    }
}
        
int
watchdog_pwd_lookup(char *pwdname, int serial, char **pwdvalue)
{
    pwddef_t *pwdp;

    *pwdvalue = 0;

    for (pwdp = pwdlist; pwdp != NULL; pwdp = pwdp->pwdnext) {

        if (!strcmp(pwdname, pwdp->pwdname)) {
            
            //
            // if we're asking for a higher serial number than we have
            // then the password must be wrong - we need to fail the
            // lookup to cause a reprompt (or a failure if we cannot
            // prompt anymore due to loss of ther terminal).
            //
            if (serial > pwdp->serial)
                return 0;

            *pwdvalue = watchdog_pwd_decrypt(&pwdp->pwdvalue);
            return 1;
        }
    }

    return 0;
}

int
watchdog_pwd_save(char *pwdname, int serial, char *pwdvalue)
{
    pwddef_t *pwdp;
    int rv = 0;

    for (pwdp = pwdlist; pwdp != NULL; pwdp = pwdp->pwdnext) {

        if (!strcmp(pwdname, pwdp->pwdname)) {
            
            /*
             * Already have this password saved, so server must be
             * reprompting.  Replace the old value with the new value.
             */

            watchdog_pwd_free(&pwdp->pwdvalue);
            watchdog_pwd_encrypt(pwdvalue, &pwdp->pwdvalue);
            pwdp->serial = serial;
            return 1;
        }
    }

    if ((pwdp = (pwddef_t *)malloc(sizeof(pwddef_t))) == NULL)
        return 0;

    pwdp->pwdname = strdup(pwdname);
    watchdog_pwd_encrypt(pwdvalue, &pwdp->pwdvalue);
    pwdp->serial = serial;
    if (pwdp->pwdvalue.len) {
        pwdp->pwdnext = pwdlist;
        pwdlist = pwdp;
        rv = 1;
    } else {
        /* watchdog_pwd_encrypt failed */
        free(pwdp);
        rv = 0;
    }
    return rv;
}

int
watchdog_pwd_prompt(const char *prompt, int serial, char **pwdvalue)
{
    char phrase[256];
    char *cp;
    int infd = fileno(stdin);
    int isTTY = isatty(infd);
    int plen;

    /* Turn off buffering to avoid leaving password in I/O buffer */
    setbuf(stdin, NULL);

    /* Prompt for password */
    if (isTTY) {
        if (serial > 0)
            fprintf(stdout, "Password incorrect. Please try again.\n");
        fprintf(stdout, "%s", prompt);
        echoOff(infd);
    } else {
        /*
         * Since stdin is not a tty, fail if the server asks
         * for the same password.  The password is invalid, and it's
         * unlikely that a non-tty stdin is going to have the valid
         * one.
         */
        if (watchdog_pwd_lookup((char *)prompt, serial, pwdvalue)) {
            if (pwdvalue && *pwdvalue) {
                free((void *)(*pwdvalue));
            }
            return -2;
        }
    }

    /* Return error if EOF */
    if (feof(stdin)) {
        if (isTTY) {
            echoOn(infd);
        }
        return -1;
    }

    cp = fgets(phrase, sizeof(phrase), stdin);

    /* EOF is more likely to be seen here */
    if (cp == NULL) {
        if (isTTY) {
            echoOn(infd);
        }
        return -1;
    }

    if (isTTY) {
        fprintf(stdout, "\n");
        echoOn(infd);
    }

    /* stomp on newline */
    plen = strlen(phrase);
    if (plen > 0) {
        phrase[--plen] = 0;
    }

    *pwdvalue = strdup(phrase);

    /* Clear password from local buffer */
    memset((void *)phrase, 0, sizeof(phrase));

    return 0;
}

