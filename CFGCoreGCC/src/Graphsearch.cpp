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

#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <stack>

#include "Graphsearch.h"

#include "stack"
#include <vector>

void Graphsearch::removelink(u32 ID, u32 IDto)
{
    dirty = true;
    for(u32 i = 0; i < data[ID].connectedwith.size();++i)
    {
        if (data[ID].connectedwith[i] == IDto)
        {
            data[ID].connectedwith.erase(data[ID].connectedwith.begin()+i);
        }
    }
}

void Graphsearch::addID(u32 ID)
{
    while(data.size()< ID + 1)
    {
        data.emplace_back(data.size());
        for (auto i = data.begin();i != data.end();++i)
            while(i->reachable.size() < ID + 1)
            i->reachable.emplace_back();
    }
    data[ID].enable = true;
}
u32 Graphsearch::isconnected(u32 ID1, u32 ID2)
{
    if (dirty)
    {
        //set all dirty
        for(auto i = data.begin(); i != data.end();++i)
        {
            i->dirty = true;
        }
        dirty = false;
    }
    if (data[ID1].dirty)
        Updatethis(ID1);
    return data[ID1].reachable[ID2];
}
void Graphsearch::Updateone(u32 ID)
{
    std::vector<bool> havvisited(data.size(),false);
    std::stack<u32> s;

    s.push(ID);
    for (u32 j = 0; j < data.size(); j++) //to visit
        havvisited[j] = false;
    while (!s.empty())
    {
        int current = s.top();
        s.pop();
        data[ID].reachable[current] = true;
        if (data[current].enable)
        {
            for (u32 j = 0; data[current].connectedwith.size() > j; j++)
            {
                if (!havvisited[data[current].connectedwith[j]])
                {
                    s.push(data[current].connectedwith[j]);
                    havvisited[data[current].connectedwith[j]] = true;
                }
            }
        }
    }
}

void Graphsearch::Update()
{
    std::vector<bool> havvisited;
    havvisited.resize(data.size());
    for (u32 i = 0; i < data.size(); i++) //set all to unreachable
        for (u32 j = 0; j < data[i].reachable.size(); j++)
            data[i].reachable[j] = 0;
    std::stack<u32> s;

    int time_to_next_phase = 0;
    int time_to_next_phase_builder = 0;
    for (u32 i = 0; i < data.size(); i++) //check each connection
    {
        int phase = 1;
        s.push(i);
        for (u32 j = 0; j < data.size(); j++) //to visit
            havvisited[j] = false;
        while (!s.empty())
        {
            int current = s.top();
            s.pop();
            if (data[current].enable)
            {
                for (u32 j = 0; data[current].connectedwith.size() > j; j++)
                {

                    if (!havvisited[data[current].connectedwith[j]])
                    {
                        data[i].reachable[data[current].connectedwith[j]] = phase;
                        s.push(data[current].connectedwith[j]);
                        time_to_next_phase_builder++;
                        havvisited[data[current].connectedwith[j]] = true;
                    }
                }
            }
            if (time_to_next_phase == 0)
            {
                phase++;
                time_to_next_phase = time_to_next_phase_builder;
                time_to_next_phase_builder = 0;
            }
            else
            {
                time_to_next_phase--;
            }
        }

    }
}

void Graphsearch::Updatethis(u32 ID)
{
    std::vector<bool> havvisited;
    havvisited.resize(data.size());
    for (u32 i = 0; i < data.size(); i++) //set all to unreachable
        for (u32 j = 0; j < data[i].reachable.size(); j++)
            data[i].reachable[j] = 0;
    std::stack<u32> s;

    int time_to_next_phase = 0;
    int time_to_next_phase_builder = 0;
    int phase = 1;
    s.push(ID);
    for (u32 j = 0; j < data.size(); j++) //to visit
        havvisited[j] = false;
    while (!s.empty())
    {
        int current = s.top();
        s.pop();
        if (data[current].enable)
        {
            for (u32 j = 0; data[current].connectedwith.size() > j; j++)
            {

                if (!havvisited[data[current].connectedwith[j]])
                {
                    data[ID].reachable[data[current].connectedwith[j]] = phase;
                    s.push(data[current].connectedwith[j]);
                    time_to_next_phase_builder++;
                    havvisited[data[current].connectedwith[j]] = true;
                }
            }
        }
        if (time_to_next_phase == 0)
        {
            phase++;
            time_to_next_phase = time_to_next_phase_builder;
            time_to_next_phase_builder = 0;
        }
        else
        {
            time_to_next_phase--;
        }
    }
    data[ID].dirty = false;
}
