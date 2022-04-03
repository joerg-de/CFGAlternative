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

#ifndef VerticalLineOwner_h
#define VerticalLineOwner_h

#include <vector>

#include "VerticalLine.h"


class VerticalLineOwner {

 public:

	virtual ~VerticalLineOwner();

    virtual bool verticalCanSeek(int xOffset, VerticalLine& line) = 0;

    virtual void verticalSeek(int xOffset, VerticalLine& line) = 0;

    virtual void attachVerticalLine(VerticalLine& line,int hintx) = 0;

    std::vector< VerticalLine* >* getVericalLinesForResort();

    void startResort();

    void endResort();

    virtual int getSeekFreeSpacePositive(VerticalLine& line);

    virtual int getSeekFreeSpaceNegative(VerticalLine& line);

    void internResort();

    bool isInside(LineBinder* binder);

    void swapLine(LineBinder* binder, VerticalLine *inLine);

    void PullVerticalLines();

    LineBinder* getInnerLineHolder(LineBinder* a,LineBinder* b);

    void DebugPrintOwnedVLines();

 protected:
    std::vector< VerticalLine* > ownedVerticalLines;
    std::vector< uint32_t > tempResort;
};

#endif // VerticalLineOwner_h
