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

#ifndef VerticalLine_h
#define VerticalLine_h

class HorizontalLine;
class CFGEdge;
class HorizontalLineOwner;
class VerticalLineOwner;
class CFGLayer;

#include "linebinder.h"


#include <memory>

class VerticalLine {

 public:

    CFGEdge* getEdge();

    int getx() const;

    int getUppery() const;

    int getLowery() const;

    VerticalLine* getFirst();

    VerticalLine* getNext();

    VerticalLine* getPrev();

    HorizontalLine* getLowerHorizont();

    HorizontalLine* getUpperHorizont();

    VerticalLineOwner* getHolder();

    void setLine(LineBinder* binder);

    int getyUp() const;

    int getyDown() const;

    bool glue(VerticalLine& next);

    bool isGlue() const;

    void attach(VerticalLineOwner& holder, int hintx);

    void setx(int x);

    bool isIOLine() const;

    void link(HorizontalLine& Horizont);

    VerticalLine(HorizontalLine* Horizont, CFGEdge& edge);

    int getLineSize() const;

    VerticalLineOwner* getOwner();

    void setOwner(VerticalLineOwner& owner);

    int getEdgeID();

    bool canSeek(int xoffset);

    void seek(int xoffset);

    LineBinder* getUsedLineBinder();


    friend class CFGLayer;
    friend class CFGNode;
    friend class VerticalLineOwner;

 private:
    HorizontalLine* upperHorizont = nullptr;
    HorizontalLine* lowerHorizont = nullptr;
    CFGEdge* edge;
    VerticalLineOwner* owner = nullptr;
    std::unique_ptr<LineBinder> ownLineBinder;
    LineBinder *usedLineBinder;
    int smoothOffset = 0;
    int x;
};

#endif // VerticalLine_h
