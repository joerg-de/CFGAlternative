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

#ifndef LINEBINDER_H
#define LINEBINDER_H


#include <list>

class VerticalLine;

class LineBinder
{
public:
    LineBinder();
    bool tryBindNext(LineBinder * next);
    void addline(VerticalLine* line);
    int getx();
    void setx(int x);
    bool canSeek(int xoffset);
    void seek(int xOffset);
    bool selfCheck();
    int getSize() const;
    int getSeekFreeSpacePositive();
    int getSeekFreeSpaceNegative();
    int getPull();
    static bool swapLineHolder(LineBinder* a, LineBinder* b);
    static LineBinder* getInnerLineHolder(LineBinder* a,LineBinder* b);
    int getStartDepth();
    std::list<VerticalLine*>* getLines();

private:
    LineBinder* getLastLineBinder();
    LineBinder* getNextLineBinder();
    int freeSmoothOffsetpos = 0;
    int freeSmoothOffsetnegative= 0;
    std::list<VerticalLine*> lines;
};

#endif // LINEBINDER_H
