/* ###
 * Copyright 2021-2022 joerg All Rights Reserved.
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ghidra.app.plugin.core.functiongraph.graph;

import java.util.Collection;
import java.util.Collections;

import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphVertexAttributes;
import ghidra.program.model.listing.Function;

/**
 * A graph for the {@link SampleGraphPlugin} that allows for filtering
 */
public class SampleGraph extends FunctionGraph {

    private Function function;
    private FunctionGraphVertexAttributes settings; // refers to vertex location info


    /**
     * Construct a function graph with the given (optional) vertices and edges
     *
     * @param function the function upon which this graph is based
     * @param settings the settings that will be used for vertices added in the future
     * @param vertices the vertices
     * @param edges the edges
     */
    public SampleGraph(Function function, FunctionGraphVertexAttributes settings,
                       Collection<FGVertex> vertices, Collection<FGEdge> edges) {
        super(function,settings,vertices,edges);
        this.function = function;
        this.settings = settings;

        vertices.forEach(v -> addVertex(v));
        edges.forEach(e -> addEdge(e));

        restoreSettings();
    }

    @Override
    public SampleGraph copy() {
        Collection<FGVertex> vertices2 = Collections.emptyList();
        Collection<FGEdge> edges2 = Collections.emptyList();
        SampleGraph newGraph = new SampleGraph(this.function, this.settings,vertices2,edges2);

        for (FGVertex v : vertices.keySet()) {
            newGraph.addVertex(v);
        }

        for (FGEdge e : edges.keySet()) {
            newGraph.addEdge(e);
        }

        return newGraph;
    }

}
