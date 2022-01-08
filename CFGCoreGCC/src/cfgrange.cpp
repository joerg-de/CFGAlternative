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

#include "cfgrange.h"

CFGRange::CFGRange()
{

}

CFGRange::~CFGRange()
{

}

void CFGRange::setRange(int start,int end)
{
    if(start < end)
    {
        this->start = start;
        this->end = end;
    }
    else
    {
        this->start = end;
        this->end = start;
    }
}

int CFGRange::getNear(int point) const
{
    if(start > point)
        return start;
    if(start < end)
        return end;
    return point;
}
void CFGRange::limmit(int& start,int& end) const
{
    if(this->start > start)
        start = this->start;
    if(this->end < end)
        end = this->end;
}
