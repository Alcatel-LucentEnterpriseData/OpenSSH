 /* copyright 2019 ALE USA Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SSH_ALU_H
#define _SSH_ALU_H
#define __ALU__

int alu_is_remote_host_allowed(char *host);

#ifdef ALU_ENHANCE_CAPABLE
#define ENHANCED_ENABLE_FILE  "/var/run/aaaEnhancedMode.enable"
int alu_is_enhanced_enable();
void alu_get_configure_enhanced_mode ();
#endif

#ifdef ALU_CC_CAPABLE
#define CC_ENABLE_FILE  "/var/run/CommonCriteria.enable"
#define CC_PREBANNER_FILE "/flash/switch/pre_banner.txt"
int alu_is_cc_enable();
void alu_get_configure_cc_mode ();
#endif

#ifdef ALU_JITC_CAPABLE	 
#define JITC_ENABLE_FILE  "/var/run/aaaJitcOper.enable"
int alu_is_jitc_enable();
void alu_get_configure_jitc_mode ();
#endif

#define MIN_ALLOW_RSA_BIT_SIZE 	2048

#endif // #ifndef _SSH_ALU_H
