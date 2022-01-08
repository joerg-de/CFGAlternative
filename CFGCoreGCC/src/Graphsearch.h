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

#pragma once

#define u32 unsigned int

#include <vector>
class Graphsearch_node
{
public:
    Graphsearch_node(int id):ID(id),enable(false) {}
    std::vector<u32> connectedwith;
    std::vector<u32> reachable;
    u32 ID;
    bool enable;
    bool dirty;
};

class Graphsearch
{

public:
    Graphsearch(){}
    void addID(u32 ID);
    void addlink(u32 ID,u32 IDto)
    {
        dirty = true;
        data[ID].connectedwith.emplace_back(IDto);
    }
    void removelink(u32 ID,u32 IDto);
    void disableID(u32 ID)
    {
        dirty = true;
        data[ID].enable = false;
    }
    void enableID(u32 ID)
    {
        dirty = true;
        data[ID].enable = true;
    }

    void Update();
    void Updatethis(u32 ID); //this updates what is connected reachable form the ID with depth
    void Updateone(u32 ID); //this updates what is connected reachable form the ID but only with true or false depth check is not happening
    u32 isconnected(u32 ID1, u32 ID2); //returns hops the ID1 has to do to get to ID2 0 if not possible

    std::vector<Graphsearch_node> data; //this contains the nodes
private:
    bool dirty;
};
