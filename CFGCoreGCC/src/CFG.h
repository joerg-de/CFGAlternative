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

#ifndef CFG_h
#define CFG_h

#include <memory>
#include <string>
#include <iostream>
#include <stack>

#include "CFGEdge.h"
#include "CFGLayer.h"
#include "CFGNode.h"

#include "Graphsearch.h"


class CFG {

 public:

    void solve(CFGNode& entry);

    void addEdge(CFGEdge& edge);

    void addNode(CFGNode& node);

    std::vector<CFGNode *>* getNodes();

    std::vector<CFGEdge *>* getEdges();

    std::vector<std::unique_ptr<CFGLayer> >* getLayers();

 private:

    void shortenUpEdges();

    void runAllNodesPlacedInLayerUpdate();

    void updateyPos();

    void setLayer(CFGNode& entry);

    void fixNodex();

	void fixNodex(CFGLayer& hint); //hint is the layer where stuff was changed making stuff faster

    void mapLines();

    void reduceKinks();

    void cleanup();

    void step1(CFGNode& entry, std::vector<bool> &washerefild, std::vector<bool> &washerefild2);

    //todo rework
    Graphsearch search;
    //todo end

    std::vector< CFGNode* > nodes;
    std::vector< CFGEdge* > edges;
	std::vector<std::unique_ptr<CFGLayer>> layers;
};

#endif // CFG_h
