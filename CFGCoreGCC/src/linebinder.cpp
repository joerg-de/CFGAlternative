/*
 * Copyright 2014-2022 joerg All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "linebinder.h"

#include "VerticalLine.h"
#include "CFGEdge.h"
#include "VerticalLineOwner.h"
#include <limits>

#include <algorithm>

#include <assert.h>

LineBinder::LineBinder()
{

}
bool LineBinder::canSeek(int xoffset)
{
    //speedup stuff
    if(xoffset == 0)
        return true;

    bool pos = false;
    if(xoffset > 0)
        pos = true;

    if(pos)
    {
        if(freeSmoothOffsetpos >= xoffset)
            return true;
    }
    else
    {
        if(freeSmoothOffsetnegative <= xoffset)
            return true;
    }
    //speedup stuff end

    for(auto line : lines)
    {
        if(!line->getOwner())
            return false;
        if(!line->getOwner()->verticalCanSeek(xoffset,*line))

            return false;
    }

    //speedup stuff
    if(pos)
    {
        freeSmoothOffsetpos = xoffset;
    }
    else
    {
        freeSmoothOffsetnegative = xoffset;
    }
    //speedup stuff end

    return true;
}
void LineBinder::seek(int xOffset)
{
    if(xOffset == 0)
        return;
    for(auto line : lines)
    {
        line->getOwner()->verticalSeek(xOffset,*line);
    }

    //speedup stuff
    freeSmoothOffsetpos = 0;
    freeSmoothOffsetnegative= 0;
    //speedup stuff end
}
bool LineBinder::selfCheck()
{
    if(lines.empty())
        return true;
    int x = (*lines.begin())->getx();
    for(auto line : lines)
    {
        if(x != line->getx() || line->getUsedLineBinder() != this)
            return false;

    }
    return true;
}

bool LineBinder::tryBindNext(LineBinder * next)
{
    if(next == this) //already bound
        return false;
    int xOut = getx();
    if(next->canSeek(xOut - next->getx()))
    {
        next->seek(xOut - next->getx());
        for(auto line : next->lines)
        {
            line->setLine(this);
        }
        next->lines.clear();
        return true;
    }

    xOut = next->getx();
    if(canSeek(xOut - getx()))
    {
        seek(xOut - getx());
        for(auto line : lines)
        {
            line->setLine(next);
        }
        lines.clear();
        return true;
    }

    return false;
}

void LineBinder::addline(VerticalLine* line)
{
    lines.push_back(line);

    //speedup stuff
    freeSmoothOffsetpos = 0;
    freeSmoothOffsetnegative= 0;
    //speedup stuff end
}
int LineBinder::getx()
{
    return (*lines.begin())->getx();
}
void LineBinder::setx(int x)
{
    for(auto line :lines)
        line->setx(x);
}

int LineBinder::getSize() const
{
    return lines.size();
}
int LineBinder::getSeekFreeSpacePositive()
{
    int ret = std::numeric_limits<int>::max();
    for(VerticalLine* line :lines)
    {
        VerticalLineOwner * temp = line->getHolder();
        if(!temp)
            return 0;
        ret = std::min(ret,temp->getSeekFreeSpacePositive(*line));
    }
    return ret;
}

int LineBinder::getSeekFreeSpaceNegative()
{
    int ret = std::numeric_limits<int>::min();
    for(VerticalLine* line :lines)
    {
        VerticalLineOwner * temp = line->getHolder();
        if(!temp)
            return 0;
        ret = std::max(ret,temp->getSeekFreeSpaceNegative(*line));
    }
    return ret;
}
static bool get_sign(int value)
{
    return (value & 0x80000000);
}
int LineBinder::getPull()
{
    LineBinder* last = getLastLineBinder();
    LineBinder* next = getNextLineBinder();
    if(!next || !last)
        return 0;
    int x1 = next->getx() - getx();
    int x2 = last->getx() - getx();
    if(get_sign(x1) != get_sign(x2))
    {
        if((*last->getLines()->begin())->getOwner() == nullptr && (*last->getLines()->begin())->getEdge()->isDown())
            return x2;
        if((*next->getLines()->begin())->getOwner() == nullptr && (*last->getLines()->begin())->getEdge()->isDown())
            return x1;
        return 0;
    }
    int xres = (std::abs(x1) > std::abs(x2)) ? x2 : x1; //todo speed up
    return xres;
}
LineBinder* LineBinder::getLastLineBinder()
{
    auto temp = (*lines.begin())->getPrev();
    while(temp)
    {
        if(std::find(lines.begin(),lines.end(),temp) == lines.end()) //the first one not in the list
            return temp->getUsedLineBinder();
        temp = temp->getPrev();
    }
    return nullptr;
}

LineBinder* LineBinder::getNextLineBinder()
{
    auto temp = (*lines.rbegin())->getNext();
    while(temp)
    {
        if(std::find(lines.rbegin(),lines.rend(),temp) == lines.rend()) //the first one not in the list
            return temp->getUsedLineBinder();
        temp = temp->getNext();
    }
    return nullptr;
}

bool LineBinder::swapLineHolder(LineBinder* a,LineBinder* b)
{
    assert(a->selfCheck());
    assert(b->selfCheck());

    int newax = b->getx();
    int newbx = a->getx();
    //check if OK
    for(VerticalLine* line : a->lines)
    {
        VerticalLineOwner * holder = line->getHolder();
        if(!holder)
            continue;
        if(holder->isInside(b)) //todo speed up
        {
            do
            {
                LineBinder* next = holder->getInnerLineHolder(a,b);
                if(!next)
                    break;
                bool ret = swapLineHolder(next,a);
                if(!ret)
                    return ret; //did not work should never happen
                newax = b->getx();
                newbx = a->getx();
                //refresh

            }
            while(true);
        }
        if(!holder->verticalCanSeek(newax - newbx,*line))
        {
            return false;
        }
    }
    for(VerticalLine* line : b->lines)
    {
        VerticalLineOwner * holder = line->getHolder();
        if(!holder)
            continue;
        if(holder->isInside(a)) //todo speed up
            continue;
        if(!holder->verticalCanSeek(newbx - newax,*line))
        {
            return false;
        }
    }

    assert(a->selfCheck());
    assert(b->selfCheck());

    //do it
    for(VerticalLine* line : a->lines)
    {
        if(line->getHolder()->isInside(b)) //todo speed up
        {
            line->getHolder()->startResort();

            line->getHolder()->swapLine(b,line);

            line->getHolder()->endResort();
        }
        else
        {
            line->getOwner()->verticalSeek(newax - newbx,*line);
        }
    }
    for(VerticalLine* line : b->lines)
    {
        if(!line->getHolder()->isInside(a)) //todo speed up
        {
            line->getOwner()->verticalSeek(newbx - newax,*line);
        }
    }
    assert(a->selfCheck());
    assert(b->selfCheck());
    return true;
    //a->setx(newax);
    //b->setx(newbx);
}
std::list<VerticalLine*>* LineBinder::getLines()
{
    return &lines;
}
