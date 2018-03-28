/*
 * Copyright (c) 2014, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/// *
//*版权所有（c）2014，Dustin Lundquist <dustin@null-ptr.net>
//* 版权所有。
//*
//*重新分配和使用源和二进制形式，有或没有
//*修改是允许的，条件是满足以下条件：
//*
//* 1.重新分发源代码必须保留上述版权声明，
//*此条件列表和以下免责声明。
//* 2.二进制格式的再分发必须重现上述版权
//*通知，此条件清单及以下免责声明
//*文件和/或与发行版一起提供的其他材料。
//*
//*本软件由版权所有者和作者按“原样”提供
//*及任何明示或暗示的保证，包括但不限于此
//*适销性和适用于特定用途的默示保证
//*免责声明 在任何情况下，版权所有者或贡献者是
//*对任何直接，间接，偶然，特殊，示范或或有任何责任
//*后果性损害（包括但不限于采购）
//*替代商品或服务; 使用，数据或利润损失; 或业务
//*中断）无论如何导致和任何责任理论，无论如何
//*合约，严格责任或侵权行为（包括疏忽或其他）
//*以任何方式使用本软件，即使已被告知
//*这种损害的可能性。
//* /
#ifndef PROTOCOL_H
#define PROTOCOL_H

typedef struct protocol {
    const int default_port;
    int(*const parse_packet)(const char *, size_t, char **);
} protocol_t;

#endif
