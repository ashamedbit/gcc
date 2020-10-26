//===-- sanitizer_watchaddrfileio.cpp ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between all the Sanitizer
// run-time libraries.
//===----------------------------------------------------------------------===//

#include "sanitizer_common.h"
#include "sanitizer_stacktrace.h"
#include "sanitizer_watchaddrfileio.h"
#include <algorithm>

namespace __sanitizer {

    //extern avl_array<uptr,BufferedStackTrace*, std::uint32_t, 5000, true> addrtowatch;
    class AddrWatch {

    public:

        const static int maxwatch = 5000;
        BufferedStackTrace watchstack[maxwatch];
        BufferedStackTrace lastusestack[maxwatch];
        BufferedStackTrace* sortedstack[maxwatch];
        bool foundthisrun[maxwatch] = {false};
        int bspos = 0;

        BufferedStackTrace* GetLastUseStack(int pos) {
            return &(lastusestack[pos]);
        }

        BufferedStackTrace* GetStack(int pos) {
            return &(watchstack[pos]);
        }

        BufferedStackTrace* InsertNewStack() {
            return GetStack(bspos++);
        }

        int GetSize(){
            return bspos;
        }

        void SetStackFoundThisRun(int pos) {
            foundthisrun[pos]=1;
        }


        AddrWatch() {

            // Read addresses to watch from file
            ReadWatchAddr();

            // Create sorted array of stacktraces through pointers
            InitandSort();
        }

        ~AddrWatch() {

            // Write Malloc stacks that were not found in this run to Address Watcher Report
            for (int i=0; i<bspos; i++)
                if (foundthisrun[i] == true)
                {
                    WriteWatchAddr(&watchstack[i]);
                    WriteWatchAddr(&lastusestack[i]);
                }

        }

        bool static CompareBufferedStackTrace(BufferedStackTrace* x, BufferedStackTrace* y);
        bool static EqualBufferedStackTrace(BufferedStackTrace* x, BufferedStackTrace* y);
        void InitandSort();
        uptr ReadUptr(char* c);
        void inline ReadStack(BufferedStackTrace* s, char** c);
        bool ReadWatchAddr();
        int IsStackPresent(BufferedStackTrace* s);
    };

    AddrWatch addrwatch;

    bool AddrWatch::EqualBufferedStackTrace (BufferedStackTrace* x, BufferedStackTrace* y)
    {
        if (x->size != y->size)
           return false;

        // Discard top and bottom line
        for (int i=1;i<(x->size)-1;i++)
            if (x->trace_buffer[i] != y->trace_buffer[i])
                return false;

        return true;
    }

    bool AddrWatch::CompareBufferedStackTrace(BufferedStackTrace* x, BufferedStackTrace* y)
    {
        if (x->size < y->size)
            return true;

        if (x->size > y->size)
            return false;

        // Discard top and bottom line
        for(int i=1; i<(x->size)-1 ;i++)
        {
            if (x->trace_buffer[i] == y->trace_buffer[i])
                continue;

            if (x->trace_buffer[i] < y->trace_buffer[i])
                return true;

            // x Greater
            return false;
        }

        // Equal Stacktraces. No need to swap
        return true;
    }

    // Binary Search our list of StackTrace pointers
    int AddrWatch::IsStackPresent(BufferedStackTrace* s)
    {
        int high = GetSize()-1;
        int low = 0;
        
        while (high >= low)
        {
            int mid = (high+low)/2;
            BufferedStackTrace* midstack = sortedstack[mid];

            if (EqualBufferedStackTrace(s,midstack))
               return mid;
            else if (CompareBufferedStackTrace(midstack,s))
                low = mid+1;
            else
                high = mid-1;

        }
        return -1;
    }

    void AddrWatch::InitandSort()
    {
        for(int i=0; i<bspos; i++)
            sortedstack[i] = GetStack(i);

        std::sort(sortedstack,sortedstack+bspos,CompareBufferedStackTrace);
    }

    uptr AddrWatch::ReadUptr(char* c)
    {
        uptr res=0;
        for (int j= sizeof(uptr)*2-1; j>=0; j--)
        {
            int val=(c[j] & 0xff);

            if (val>=97)
                val=val-87;
            else
                val=val-48;

            res =res | val;

            if (j!=0)
                res=(res<<4);
        }
        return res;
    }

    void inline AddrWatch::ReadStack(BufferedStackTrace* s, char** c)
    {
        s->size = ReadUptr(*c);

        *c=*c+sizeof(uptr)*2;
        //Printf("And the size is!!! %zu : \n",s->size);

        for (uptr k=0;k<s->size;k++)
        {
            s->trace_buffer[k] = ReadUptr(*c);
            *c=*c+sizeof(uptr)*2;
            //Printf("And The value is FUCCK!!! %zu : \n",s->trace_buffer[k]);
        }
    }

    bool AddrWatch::ReadWatchAddr()
    {
        char* c;
        uptr csize=0;
        uptr read_len=0;
        uptr max_len=10000;
        bool opened=ReadAddrReportToBuffer(&c,&csize,&read_len,max_len);

        if (!opened)
            return false;

        char* p=c;
        int scannedstacks=0;
        while (*p)
        {
            BufferedStackTrace* s = this->InsertNewStack();
            ReadStack(s,&p);

            BufferedStackTrace* ls = this->GetLastUseStack(scannedstacks);
            ReadStack(ls,&p);
            scannedstacks++;
        }
        return true;
    }

    bool inline WriteUptr(uptr x, char* c)
    {
        for (int i=0;i<sizeof(uptr)*2;i++)
        {
            c[i]= (x & 0xf) + 48;

            if (c[i]>=58)
               c[i]=c[i]+39;

            x=(x>>4);
        }
        WatchAddrRawWrite(c);

        return true;
    }

    bool WriteWatchAddr(StackTrace* s)
    {
        char c[sizeof(uptr)*2+1];
        c[sizeof(uptr)*2]='\0';

        // Can be used when there is no last use during a run
        if (s == nullptr)
        {
            WriteUptr(0,c);
            return true;
        }

        WriteUptr(s->size,c);

        for (int i=0; i<(s->size); i++)
        {
            WriteUptr(s->trace[i],c);
        }
        return true;
    }
    
    bool WriteWatchAddr(BufferedStackTrace* s)
    {
        char c[sizeof(uptr)*2+1];
        c[sizeof(uptr)*2]='\0';

        // Can be used when there is no last use during a run
        if (s == nullptr)
        {
            WriteUptr(0,c);
            return true;
        }

        WriteUptr(s->size,c);

        for (int i=0; i<(s->size); i++)
        {
            WriteUptr(s->trace_buffer[i],c);
        }
        return true;
    }
 
    bool IsAddrToWatch(BufferedStackTrace *s)
    {
        int pos = addrwatch.IsStackPresent(s); 
        if (pos == -1)
            return false;

        return true;
    }

    BufferedStackTrace* GetPrevRunLastUse(BufferedStackTrace *s)
    {
        int pos = addrwatch.IsStackPresent(s);

        if (pos == -1)
            return nullptr;

        addrwatch.SetStackFoundThisRun(pos);
        return addrwatch.GetLastUseStack(pos);
    }


    BufferedStackTrace* MergeLastUse(BufferedStackTrace* x, BufferedStackTrace* y)
    {
        if ((x != nullptr) && (x->size<3))
            x=nullptr;

        if ((y != nullptr) && (y->size<3))
            y=nullptr;


        if ((x == nullptr) && (y==nullptr))
            return nullptr;

        if (x==nullptr)
            return y;

        if (y==nullptr)
            return x;

        int xbottom = x->size-3;
        int ybottom = y->size-3;

        while ((xbottom >= 0) && (ybottom >= 0))
        {
            if (x->trace_buffer[xbottom] > y->trace_buffer[ybottom])
            {
                return x;
            }

            if (x->trace_buffer[xbottom] < y->trace_buffer[ybottom])
            {
                return y;
            }

            xbottom--;
            ybottom--;
        }

        return x;
    }

}
