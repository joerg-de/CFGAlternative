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

#ifndef CFGLayer_h
#define CFGLayer_h

#include <vector>

class CFGNode;
class CFGLayer;
#include "VerticalLineOwner.h"
#include "HorizontalLineOwner.h"


template <typename T>
bool IsInBounds(const T& value, const T& low, const T& high) {
    return !(value <= low) && (value <= high);
}

template <typename T>
bool IsInBounds(const T& low1,const T& high1, const T& low, const T& high) {
    return IsInBounds(low,low1,high1) ||
           IsInBounds(high,low1,high1) ||
           IsInBounds(high1,low,high);
}

class CFGLayer : public VerticalLineOwner, public HorizontalLineOwner {

 public:

    CFGLayer(CFGLayer* prev);

    void routeLines();

    void addNode(CFGNode& Node);

    void addNext(CFGLayer& next);

    bool isNodeAtRange(unsigned int from,unsigned int to) const;

    void sety(int y);

    void updateySize();

    int minyAtRange(int from, int to) const; //todo

    CFGNode* getMostRightNode();

    CFGNode* getMostLeftNode();

    CFGNode* getRightOfx(int xpoint);

    bool verticalCanSeek(int xOffset, VerticalLine& line);

    void verticalSeek(int xOffset, VerticalLine& line);

    void attachVerticalLine(VerticalLine& line, int hintx);

    void attachHorizontalLine(HorizontalLine& line);

    void hideLine(HorizontalLine& line);

    bool internUpdateNodex();

    std::vector< CFGNode* >* getNodes();

    int getDepth() const;

    void linkToNext(HorizontalLine& templine);

    void fixAttachedx();

    CFGLayer * getNext();

    CFGLayer * getPrev();

    void sortHorizontalLines();

    void updateyIO();

    int Fixy(HorizontalLine * line);

    int getSeekFreeSpaceNegative(VerticalLine& line);

 private:

    int getMaxNodey(int left, int right);

    int getMaxyTillLine(int left, int right, HorizontalLine * endLine);

    int getMinyTillLineReverse(int left, int right,HorizontalLine * endLine);

    int FixyReversed(HorizontalLine * line);

    std::vector<HorizontalLine *> innerSortHorizontalLines(std::vector< HorizontalLine* >::iterator begin,std::vector< HorizontalLine* >::iterator end, int type);

    int depth;
    unsigned int height;
    unsigned int yPos;
    std::vector< CFGNode* > nodes;
    CFGLayer* prev;
    CFGLayer* next = nullptr;
};

#endif // CFGLayer_h
