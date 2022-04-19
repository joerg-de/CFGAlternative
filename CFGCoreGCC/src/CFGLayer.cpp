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

#include "CFGLayer.h"
#include "CFGNode.h"
#include "CFGEdge.h"
#include "cfgrange.h"

#include "settings.h"

#include <list>
#include <cmath>
#include <limits>
#include <algorithm>
#include <ranges>
#include <stdio.h>

static bool inrange(int val,int range)
{
    if(-range < val && val < range)
        return true;
    else
        return false;
}

CFGLayer::CFGLayer(CFGLayer* prev)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B10 begin
{
    this->prev = prev;
    if(prev == nullptr)
    {
        depth = 0;
    }
    else
    {
        depth = prev->depth + 1;
        prev->addNext(*this);
    }
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B10 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

void CFGLayer::routeLines()
{
    //set all routes for the lines in the layer
	for(auto templine : ownedHorizontalLines)
    {
        if(templine->getLowerVertical()->isIOLine())
            continue;

        VerticalLine* line = templine->getLowerVertical();
        int inLinex = templine->getUpperVertical()->getx();
        CFGEdge::Binding bind = line->getEdge()->getBinding();
        //if no binding update binding
        if(bind == CFGEdge::Binding::NotSet)
        {
            if(line->getLineSize() >= 3) //if we are bigger than 2 we place the line on the left or right so we calculate the shortest route
            {
                //get the shortest way
                int maxRight = 0;
                int minLeft = 0;
                HorizontalLine* current = templine;
                while(current)
                {
                    CFGNode* rightNode = current->getLayer()->getMostRightNode();
                    if(!rightNode)
                    {
                        current = current->getNext();
                        continue;
                    }
                    int right = rightNode->getx() + rightNode->getWidth();
                    maxRight = right > maxRight ? right : maxRight;

                    CFGNode* leftNode = current->getLayer()->getMostLeftNode();
                    int left = leftNode->getx();
                    minLeft = left < minLeft ? left : minLeft;

                    current = current->getNext();
                }
                if(std::abs(inLinex - maxRight) > std::abs(inLinex - minLeft))
                    bind = CFGEdge::Binding::Left;
                else
                    bind = CFGEdge::Binding::Right;
            }
            else
            {
                bind = CFGEdge::Binding::None;
            }
            line->getEdge()->setBinding(bind);
        }

        //the actual mapping
        switch(bind)
        {
        case CFGEdge::Binding::None:
            next->linkToNext(*templine);
            break;
        case CFGEdge::Binding::Right:
            line->attach(*next->getMostRightNode(),inLinex);
            break;
        case CFGEdge::Binding::Left:
            line->attach(*next,inLinex);
            break;
        case CFGEdge::Binding::NotSet:
            break;
        }
    }
}

void CFGLayer::addNode(CFGNode &Node)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B12 begin
{
    nodes.push_back(&Node);
    Node.setLayer(*this);
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B12 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

void CFGLayer::addNext(CFGLayer& next)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B15 begin
{
    this->next = &next;
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B15 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

bool CFGLayer::isNodeAtRange(unsigned int from,unsigned int to) const
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B24 begin
{
    for(CFGNode* node : nodes)
    {
        if(IsInBounds(-verticalNodeOffset + node->getx(),from,to))
        {
            return true;
        }
    }
    return false;
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B24 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

 std::vector< CFGNode* >* CFGLayer::getNodes()
 {
     return &nodes;
 }

 int CFGLayer::getDepth() const
 {
     return depth;
 }
 void CFGLayer::linkToNext(HorizontalLine &templine)
 {
     //attache to the nearest Node
     int oldx = templine.getUpperVertical()->getx();
     int targetx = templine.getEdge()->getLowernEndx();
     CFGNode* bestNode =nullptr;
     int bestNodeQuant = std::numeric_limits<int>::max();


     //find the best node to attache to
	 for(auto node :nodes)
     {
         int diff1 = node->getx() + node->getWidth() - oldx;
         int diff2 = node->getx() + node->getWidth() - targetx;
         int currentQuant = std::abs(diff1);//the diff we have to travel
         currentQuant += std::abs(diff2)*2;
         if(bestNodeQuant > currentQuant)
         {
             bestNode = node;
             bestNodeQuant = currentQuant;
         }
     }

     //check if the layer is better
     int currentQuant = std::abs(getMostLeftNode()->getx() - oldx);//the diff to the node we want to reach
     currentQuant += std::abs(getMostLeftNode()->getx() - targetx)*2;
     if(bestNodeQuant > currentQuant)
     {
         bestNode = nullptr;
         bestNodeQuant = currentQuant;
     }
     if(bestNode)
     {
         bestNode->attachVerticalLine(*templine.getLowerVertical(),targetx);
     }
     else
     {
         /*next->*/attachVerticalLine(*templine.getLowerVertical(),targetx);
     }
}
CFGLayer * CFGLayer::getNext()
{
    return next;
}
CFGLayer * CFGLayer::getPrev()
{
    return prev;
}

void CFGLayer::fixAttachedx()
{
    int currentx;
    CFGNode * mostLeft = getMostLeftNode();

    if(mostLeft)
       currentx = mostLeft->getx();
    else
        currentx = 0; //there are no Nodes in here so set it to any value that is constant in all runs
    for(auto Vline : ownedVerticalLines)
    {
        currentx -= IOhorizontalLineOffset;
        //currentx += Vline->smoothOffset; //only makes stuff slower
        Vline->setx(currentx);
    }

}

//this finds overlapping CFGNodes in the Layer and places them so that they don't overlay
bool CFGLayer::internUpdateNodex()
{
    bool donesomething = false; //we need to keep doing this until no overlapping
	for(auto node : nodes)
    {
        //finds the one the overlap and mix it into a new space with max and min
        //we start with the current one
        int minx = node->getx(); //this is the new box
        int maxx = node->getx() + node->getWidth() + horizontalverticalNodeOffset - 1;
        std::list<CFGNode *> lis;
        lis.push_back(node);

        bool foundsome;
        do
        {
            foundsome = false;
			for(auto is : nodes)
            {
                //check if node2 overlaps
                int newend = is->getx() + is->getWidth() + horizontalverticalNodeOffset - 1;
                if((minx <= is->getx() && is->getx() <= maxx) || (minx <= newend && newend<= maxx))
                {
                    bool foundin = false;
					for(auto i : lis)
                    {
                        if(i == is)
                            foundin = true;
                    }
                    if(!foundin)   // the block is not in the list
                    {
                        newend++;
                        foundsome = true;

                        //calculate the new size of the space and placed the node at the correct position in the list (reversed)
                        int minxmin = minx - is->getWidth();
                        double factor = (double)(is->getx() - minxmin)/(double)(maxx - minxmin);
                        maxx += ceil(factor*(is->getWidth() + horizontalverticalNodeOffset));
                        minx -= ceil((1.0 - factor)*(is->getWidth() + horizontalverticalNodeOffset));

                        auto i = lis.begin(); //sort by x
                        for(; i != lis.end(); ++i)
                        {
                            if((*i)->getx() <= is->getx())
                                break;
                        }
                        lis.insert(i,is);
                    }
                }
            }
        }
        while(foundsome);

        if(lis.size() > 1)   //if some overlap
        {
            donesomething = true;
            int current = minx; // we start at minx and place them from there one
            for(auto i = lis.rbegin(); i != lis.rend(); ++i)   //the list is reversed
            {
                CFGNode * no = *i;
                int diff = current - no->getx();
                current += no->getWidth() + horizontalverticalNodeOffset;
                no->seekPosition(diff);
            }
        }
    }
    return donesomething;
}


void CFGLayer::sety(int y)
{
    yPos = y;
}
std::vector< HorizontalLine* > CFGLayer::innerSortHorizontalLines(std::vector< HorizontalLine* >::iterator begin,std::vector< HorizontalLine* >::iterator end, int type)
{
	auto sr = std::ranges::subrange(begin, end);
    std::vector<unsigned int> upperlines(sr.size());
    std::vector<bool> usedlines(sr.size(),false);

    std::vector< HorizontalLine* > newVector;

    newVector.reserve(sr.size());

    for(unsigned int i = 0; i < sr.size();++i)
    {
        upperlines[i] = begin[i]->getAboveList(begin,end).size();
    }

    while(newVector.size() != sr.size())
    {
        //find best
    	unsigned int best;
        unsigned int quantum = std::numeric_limits<int>::max();

        for(unsigned int i = 0;i < sr.size();++i)
        {
            if(usedlines[i] == false && (quantum > upperlines[i] ||
            		(quantum == upperlines[i] && sr[best]->getEdge()->getSrc()->getx() < sr[i]->getEdge()->getSrc()->getx())) )
            {
            	bool overlap = false;
            	//check if there is a line that can overlap and skip that
            	if(begin[i]->isDown() && begin[i]->getNext() == nullptr)
            	{
            		for(unsigned int j = 0;j < sr.size();++j)
            	    {
            	    	//check if there is a line that can overlap
            	    	if(j != i && !usedlines[j] && begin[j]->isDown() && begin[j]->getPrev() == nullptr)
            	    	{
            	    		if (begin[j]->getxToUpperVertical() == begin[i]->getxToLowerVertical())
            	    		{
            	    			overlap = true;
            	    		}
            	    	}
                    }
            	}
            	if(!overlap)
            	{
            		best = i;
                	quantum = upperlines[i];
            	}
            }
        }

        //place best
        usedlines[best] = true;
        newVector.push_back(sr[best]);

    }
    return newVector;

}

void CFGLayer::sortHorizontalLines()
{
    if(ownedHorizontalLines.empty())
        return;
    std::sort(ownedHorizontalLines.begin(),ownedHorizontalLines.end(),
              [](HorizontalLine* a , HorizontalLine* b)
    {
        int aChange = a->isAngleChange();
        int bChange = b->isAngleChange();
        /*if(aChange == bChange)
        {
            return a->getxToUpperVertical() < b->getxToUpperVertical();
        }
        else*/
        {
            return aChange < bChange;
        }
    });
    std::vector< HorizontalLine* >::iterator begin1 = ownedHorizontalLines.begin();
    while(begin1 != ownedHorizontalLines.end())
    {
        if((*begin1)->isAngleChange() != 0)
            break;
        ++begin1;
    }

    std::vector< HorizontalLine* >::iterator begin2 = begin1;
    while(begin2 != ownedHorizontalLines.end())
    {
        if((*begin2)->isAngleChange() != 1)
            break;
        ++begin2;
    }

    auto temp1 = innerSortHorizontalLines(ownedHorizontalLines.begin(),begin1,0);
    auto temp2 = innerSortHorizontalLines(begin1,begin2,1);
    auto temp3 = innerSortHorizontalLines(begin2,ownedHorizontalLines.end(),2);

    ownedHorizontalLines.clear();
    ownedHorizontalLines.insert(ownedHorizontalLines.end(), temp1.begin(), temp1.end());
    ownedHorizontalLines.insert(ownedHorizontalLines.end(), temp2.begin(), temp2.end());
    ownedHorizontalLines.insert(ownedHorizontalLines.end(), temp3.begin(), temp3.end());


    //find and eliminate vertical overlap (in rare may not working if goto is used)
    bool swaped = true;
    //don't check the most upper
    for(unsigned int k = 0;k<ownedHorizontalLines.size() && swaped;++k) //Retries to make sure that there is no double overlayer
    {
        swaped = false;
        for(auto i = ownedHorizontalLines.begin();i != ownedHorizontalLines.end();++i)
        {
            for(auto j = i + 1;j != ownedHorizontalLines.end();++j)
            {

                if((*j)->isAngleChange() == 2)
                {
                    int ix = (*i)->getxToLowerVertical();
                    int jx = (*j)->getxToLowerVertical();
                    int res = ix - jx;
                    if(inrange(res,horizontalLineOffset/2 + 1))
                    {
                        std::iter_swap(j,i);
                        swaped = true;
                        break;
                    }
                }
                else if(inrange((*i)->getxToLowerVertical() - (*j)->getxToUpperVertical(),horizontalLineOffset/2 + 1))
                {
                    if((*i)->isAngleChange() == 2)
                        continue;
                    std::iter_swap(j,i);
                    swaped = true;
                    break;
                }
            }
        }
    }
}

void CFGLayer::updateySize()
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B2A begin
{
    if(prev)
        yPos = prev->yPos + prev->height + verticalNodeOffset;
    height = 0;
	for(auto node : nodes)
    {
        node->sety(yPos);
        if(height < node->getHeight())
            height = node->getHeight();
    }
	for(auto line : ownedHorizontalLines)
    {
        unsigned int newy = Fixy(line) + horizontalLineOffset;
        height  = std::max(height, newy - yPos);
        line->sety(newy);
    }

    for(auto line = ownedHorizontalLines.rbegin(); line != ownedHorizontalLines.rend();++line)
    {
        if((*line)->isAngleChange() != 2)
            continue;
        unsigned int newy = FixyReversed(*line);
        (*line)->sety(newy);
    }

    //the y pos must be somewhere in between the start and the end dose not matter where
    for(auto line : hiddenOwnedHorizontalLines)
    {
        line->sety(yPos);
    }
}

int CFGLayer::FixyReversed(HorizontalLine * line)
{
    int upx = line->getxToLowerVertical();
    int downx = line->getxToUpperVertical();
    int left = std::min(upx,downx);
    int right = std::max(upx,downx);

    unsigned int x2 = getMinyTillLineReverse(left,right,line);
    return std::min(yPos + height,x2 - horizontalLineOffset);
}

int CFGLayer::Fixy(HorizontalLine * line)
{
    int upx = line->getxToLowerVertical();
    int downx = line->getxToUpperVertical();
    int left = std::min(upx,downx);
    int right = std::max(upx,downx);

    unsigned int x1 = getMaxNodey(left,right) + yPos;
    unsigned int x2 = getMaxyTillLine(left,right,line);
    return std::max(x1,x2);
}

int CFGLayer::getMaxNodey(int left, int right)
{
    unsigned int ret = std::numeric_limits<unsigned int>::min();
    for(auto node : nodes)
    {
        //todo speed up
        bool overlap = IsInBounds(node->getx(),node->getx() + (int)(node->getWidthBox()),(int)(left - horizontalLineOffset/2),(int)(right + horizontalLineOffset/2));
        bool bigger = ret < node->getHeight();
        if(overlap&&bigger)
            ret = node->getHeight();

    }
    return ret;
}
int CFGLayer::getMaxyTillLine(int left, int right,HorizontalLine * endLine)
{
    unsigned int ret = std::numeric_limits<unsigned int>::min();
    for(HorizontalLine* line : ownedHorizontalLines)
    {
        if(endLine == line)
            break;
        /*if((IsInBounds(line->getLeftx(),(int)(left - horizontalLineOffset/2),(int)(right + horizontalLineOffset/2)) ||
           IsInBounds(line->getRightx(),(int)(left - horizontalLineOffset/2),(int)(right + horizontalLineOffset/2)) ||
           IsInBounds(left,line->getRightx(),line->getLeftx()))&&*/
        if((IsInBounds(left,(int)(line->getLeftx() - horizontalLineOffset/2),(int)(line->getRightx() + horizontalLineOffset/2)) ||
           IsInBounds(right,(int)(line->getLeftx() - horizontalLineOffset/2),(int)(line->getRightx() + horizontalLineOffset/2)) ||
           IsInBounds(line->getLeftx(),left,right))&&
           ret < line->gety())
            ret = line->gety();

    }
    return ret;
}
int CFGLayer::getMinyTillLineReverse(int left, int right,HorizontalLine * endLine)
{
    unsigned int ret = std::numeric_limits<unsigned int>::max();
    for(auto line = ownedHorizontalLines.rbegin(); line != ownedHorizontalLines.rend();++line)
    {
        if(endLine == *line)
            break;
        if((IsInBounds(left,(int)((*line)->getLeftx() - horizontalLineOffset/2),(int)((*line)->getRightx() + horizontalLineOffset/2)) ||
           IsInBounds(right,(int)((*line)->getLeftx() - horizontalLineOffset/2),(int)((*line)->getRightx() + horizontalLineOffset/2)) ||
           IsInBounds((*line)->getLeftx(),left,right))&&
           ret > (*line)->gety())
            ret = (*line)->gety();

    }
    return ret;
}

void CFGLayer::updateyIO()
{
    for(auto line : hiddenOwnedHorizontalLines)
    {
        if(line->isFirst())
            line->sety(line->getEdge()->getSrc()->getHeight() + line->getEdge()->getSrc()->gety());
        else if(line->isLast())
            line->sety(line->getEdge()->getDest()->gety());
    }
}

// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B2A end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

CFGNode* CFGLayer::getMostRightNode()
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B34 begin
{
    CFGNode* ret = nullptr;
    int currentx = std::numeric_limits<int>::min();
	for(auto node : nodes)
    {
        if(node->getx() > currentx)
        {
            ret = node;
            currentx = node->getx();
        }
    }
    return ret;
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B34 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

CFGNode* CFGLayer::getMostLeftNode()
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B36 begin
{
    CFGNode* ret = nullptr;
    int currentx = std::numeric_limits<int>::max();
	for(auto node : nodes)
    {
        if(node->getx() < currentx)
        {
            ret = node;
            currentx = node->getx();
        }
    }
    return ret;
}

CFGNode* CFGLayer::getRightOfx(int xpoint)
{
    int bestQuant = std::numeric_limits<int>::max();
    CFGNode* bestNode = nullptr;
	for(auto node : nodes)
    {
        if(xpoint < node->getx())
        {
            int currentQuant = std::abs(node->getx() - xpoint);
            if(currentQuant < bestQuant)
            {
                bestQuant = currentQuant;
                bestNode = node;
            }
        }
    }
    return bestNode;
}

// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000B36 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

bool CFGLayer::verticalCanSeek(int xOffset, VerticalLine &line)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000C20 begin
{
    //qDebug() << depth << line.getEdgeID() << xOffset;
    //don't change the order
    if(line.smoothOffset + xOffset > 0)
    {

        auto previtter = ownedVerticalLines.begin();
        while(*previtter != &line)
            ++previtter;
        if(previtter == ownedVerticalLines.begin())
            return false;
        --previtter;
        return (*previtter)->getUsedLineBinder()->canSeek(line.smoothOffset + xOffset);
    }
    if(&line == *ownedVerticalLines.rbegin())
    {
        return true;
    }
    else
    {

        //get the next in line
        auto nextitter = ownedVerticalLines.begin();
        while(*nextitter != &line)
            ++nextitter;
        ++nextitter;


        int offsetNededForNext =-((*nextitter)->smoothOffset - xOffset);

        if(offsetNededForNext < 0)
            return (*nextitter)->getUsedLineBinder()->canSeek(offsetNededForNext);
        else
            return true;
    }
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000C20 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

void CFGLayer::verticalSeek(int xOffset, VerticalLine& line)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000C28 begin
{

    if(line.smoothOffset + xOffset > 0)
    {

        auto previtter = ownedVerticalLines.begin();
        while(*previtter != &line)
            ++previtter;
        --previtter;
        (*previtter)->getUsedLineBinder()->seek(line.smoothOffset + xOffset);
    }

    if(&line == *ownedVerticalLines.rbegin())
    {
        line.smoothOffset += xOffset;
        line.setx(line.getx() + xOffset);
        return;
    }
    //get the next in line
    auto nextitter = ownedVerticalLines.begin();
    while(*nextitter != &line)
        ++nextitter;
    ++nextitter;

    //correct the vals for this and the next (next must be fixed)
    line.smoothOffset += xOffset;
    line.setx(line.getx() + xOffset);
    //this dose not change x!!!
    (*nextitter)->smoothOffset -= xOffset;

    //fix the next
    int offsetNededForNext = -(*nextitter)->smoothOffset;
    if(offsetNededForNext < 0)
    {
        (*nextitter)->getUsedLineBinder()->seek(offsetNededForNext);
    }
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:0000000000000C28 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

void CFGLayer::attachVerticalLine(VerticalLine &line, int hintx)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BAF begin
{
    ownedVerticalLines.push_back(&line);
    CFGRange r;
    CFGNode * LeftNode = getMostLeftNode();
    if(LeftNode)
    {
        r.setRange(std::numeric_limits<int>::min(),getMostLeftNode()->getx());
        line.setx(r.getNear(hintx));
    }
    else
    {
        line.setx(hintx);
    }

    line.setOwner(*this);

}
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BAF end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

void CFGLayer::attachHorizontalLine(HorizontalLine &line)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20--6e114003:1507706b3d9:-8000:0000000000000C0F begin
{
    ownedHorizontalLines.push_back(&line);
    line.setLayer(*this);
}
// section -64--88--78-20--6e114003:1507706b3d9:-8000:0000000000000C0F end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element
void CFGLayer::hideLine(HorizontalLine& line)
{
    for(auto i = ownedHorizontalLines.begin();i != ownedHorizontalLines.end();++i)
    {
        if(*i == &line)
        {
            hiddenOwnedHorizontalLines.push_back(&line);
            ownedHorizontalLines.erase(i);
            break;
        }
    }
}
int CFGLayer::getSeekFreeSpaceNegative(VerticalLine& line)
{
    return std::numeric_limits<int>::min();
}
