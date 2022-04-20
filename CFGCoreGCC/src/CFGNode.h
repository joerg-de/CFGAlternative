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

#ifndef CFGNode_h
#define CFGNode_h

#include <vector>

#include "VerticalLineOwner.h"

#include <unordered_set>


class CFGLayer;

class CFGNode : public VerticalLineOwner {

 public:

    CFGNode(int Width, int Height, int Id);

    virtual ~CFGNode();

    void setLayer(CFGLayer& layer);

    int getCenterx() const;

    void setCenterx(int x);

    void setCenterxAuto();

    void seekPosition(int x);

    void hasplaced(CFGNode& Child);

    void gotPlaced(CFGNode& Mother);

    void fixIOx();

    int getBoxCenterx();

    bool verticalCanSeek(int xOffset, VerticalLine& line);

    void verticalSeek(int xOffset, VerticalLine& line);

    void attachVerticalLine(VerticalLine& line, int hintx);

    int getx() const;

    int gety() const;

    void sety(int y);

    unsigned int getWidth() const;

    unsigned int getHeight() const;

    unsigned int getWidthBox() const;

    void setWidthBox(int x);

    int getDepth() const;

    void setDepth(int depth);

    void addOutEdge(CFGEdge& edge);

    void addInEdge(CFGEdge &edge);

    std::vector< CFGEdge* >* getOutEdges();

    std::vector< CFGEdge* >* getInEdges();

    int getID() const;

    CFGNode* getNextNodeInLine();

    CFGNode* getPrefNodeInLine();

    void fixAttachedx();

    void resortIOx();

    int getSeekFreeSpacePositive(VerticalLine& line);

    bool selfCheck();

 private:

    bool tryFixIx(int maxSkips);

    int depth = 0;
    CFGLayer* layer;
    std::vector< CFGEdge* > inEdge;
    std::vector< CFGEdge* > outEdge;
    int width;
    int height;
    int id;
    std::vector< CFGNode* > placed;
    CFGNode* mother;
    int x;
    int y;
    int widthBox;
};

#endif // CFGNode_h
