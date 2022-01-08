/* ###
 * Copyright 2021-2022 joerg All Rights Reserved.
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

package cfgalternative;

import java.awt.Shape;
import java.awt.geom.Point2D;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.SampleGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.layout.LayoutPositions;
import ghidra.util.task.TaskMonitor;

public class CFGNativeAdapter {
    static public LayoutPositions<FGVertex, FGEdge> calculateLocations(VisualGraph<FGVertex, FGEdge> visualGraph,
            VisualGraphView<FGVertex, FGEdge, SampleGraph> view,
            TaskMonitor taskMonitor) {
    	//trivial cases
        int vertexCount = visualGraph.getVertexCount();
        if (vertexCount == 0) {
            return LayoutPositions.createEmptyPositions();
        }

        //results to return
        Map<FGVertex, Point2D> newVertexLocations = new HashMap<FGVertex, Point2D>();
        Map<FGEdge, List<Point2D>> edgeArticulations = new HashMap<FGEdge, List<Point2D>>();

        //input lists
        ArrayList<FGVertex> allV = new ArrayList<FGVertex>(visualGraph.getVertices());
        ArrayList<FGEdge> allE = new ArrayList<FGEdge>(visualGraph.getEdges());
        allE.removeIf(p -> p.getEnd() == p.getStart());
        
        //buffer to send to NamedPipe
        ByteBuffer b = ByteBuffer.allocate(4 + 8*allV.size() + 4 + 12*allE.size() + 4);
        b.order(ByteOrder.LITTLE_ENDIAN);
        
        //this is only possible on the second run so don't do anything
        GraphViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
        if (viewer == null)
        {
            return LayoutPositions.createNewPositions(newVertexLocations, edgeArticulations);
        }
        

        RandomAccessFile pipe = null;
        // Connect to the pipe if the pipe is not there start the service
        try 
        {
            pipe = new RandomAccessFile("\\\\.\\pipe\\CFGPipe3953956285", "rw");
        } catch (Exception e) 
        {
            String executableName = "CFGCoreGCC" + Platform.CURRENT_PLATFORM.getExecutableExtension();
            File commandPath;
			try {
				commandPath = Application.getOSFile(executableName);
	            Runtime.getRuntime().exec(commandPath.getAbsolutePath());
	            Thread.sleep(3000);
	            pipe = new RandomAccessFile("\\\\.\\pipe\\CFGPipe3953956285", "rw");
			} 
			catch (IOException | InterruptedException e1) //something went wrong
			{
				e1.printStackTrace();
				return LayoutPositions.createNewPositions(newVertexLocations, edgeArticulations);
			}
        }
        try {
        	//send Nodes
            b.putInt(allV.size());
            for (FGVertex v : allV)
            {
                Shape shape = viewer.getRenderContext().getVertexShapeTransformer().apply(v);
                double width = shape.getBounds2D().getWidth();
                double height = shape.getBounds2D().getHeight();

                b.putFloat((float)(width));
                b.putFloat((float)(height));
            }
            b.putInt(allE.size());
            
            //send Edges
            for (FGEdge v : allE)
            {
                b.putInt(allV.indexOf(v.getStart()));
                b.putInt(allV.indexOf(v.getEnd()));
                b.putInt(0);
            }

            //get start and Start Process
            int startNode = 0;
            for(; startNode < allV.size(); startNode++) {
                if (allV.get(startNode).isEntry())
                {
                    break;
                }
            }
            b.putInt(startNode);
            pipe.write(b.array());
            pipe.getFD().sync();

            //recv Nodes
            for (FGVertex v : visualGraph.getVertices())
            {
                byte[] dest = new byte[4];
                pipe.readFully(dest);
                int x = ByteBuffer.wrap(dest).order(ByteOrder.LITTLE_ENDIAN).getInt();
                pipe.readFully(dest);
                int y = ByteBuffer.wrap(dest).order(ByteOrder.LITTLE_ENDIAN).getInt();

                Shape shape = viewer.getRenderContext().getVertexShapeTransformer().apply(v);
                double width = shape.getBounds2D().getWidth();
                double height = shape.getBounds2D().getHeight();

                Point2D location = new Point2D.Float((float)(x + width/2), (float)(y + height/2));
                newVertexLocations.put(v, location);
            }
            
            //recv Edges
            byte[] ByteNumEdges = new byte[4];
            pipe.readFully(ByteNumEdges);
            int EdgeNum = ByteBuffer.wrap(ByteNumEdges).order(ByteOrder.LITTLE_ENDIAN).getInt();
            for (int i = 0; i < EdgeNum; i++)
            {
            	//get Edge Header
            	byte[] EdgeHeader = new byte[12];
                pipe.readFully(EdgeHeader);
                ByteBuffer EdgeHeaderBB = ByteBuffer.wrap(EdgeHeader).order(ByteOrder.LITTLE_ENDIAN);
                int pointNum = EdgeHeaderBB.getInt();
                int srcID = EdgeHeaderBB.getInt();
                int endID = EdgeHeaderBB.getInt();
                List<Point2D> points = new ArrayList<>();
                int x1 = 0;
                int x2 = 0;
                int y = 0;
                
                //get Edge data
            	byte[] EdgeData = new byte[12*pointNum];
                pipe.readFully(EdgeData);
                ByteBuffer EdgeDataBB = ByteBuffer.wrap(EdgeData).order(ByteOrder.LITTLE_ENDIAN);
                for(int j = 0; j < pointNum; j++)
                {
                    x1 = EdgeDataBB.getInt();
                    x2 = EdgeDataBB.getInt();
                    y = EdgeDataBB.getInt();

                    //make sure the beginning line is vertical
                    if (j == 0)
                    {
                    	var render = viewer.getRenderContext().getVertexShapeTransformer();
                        Shape shape = render.apply(allV.get(srcID));
                        double height = shape.getBounds2D().getHeight();
                        Point2D pStart = new Point2D.Float(x1, (float)(newVertexLocations.get(allV.get(srcID)).getY() - height/2));
                        points.add(pStart);
                    }
                    
                    //add the Point
                    Point2D p1 = new Point2D.Float(x1, y);
                    Point2D p2 = new Point2D.Float(x2, y);
                    points.add(p1);
                    points.add(p2);
                }
                
                //make sure the end line is vertical
                Shape shape = viewer.getRenderContext().getVertexShapeTransformer().apply(allV.get(endID));
                double height = shape.getBounds2D().getHeight();
                Point2D pEnd = new Point2D.Float(x2, (float)(newVertexLocations.get(allV.get(endID)).getY() + height/2));
                points.add(pEnd);
                
                //find the edge the points relate to
                FGEdge ed = null;
                for (FGEdge v : allE)
                {
                    int sID = allV.indexOf(v.getStart());
                    int eID = allV.indexOf(v.getEnd());
                    if (sID == srcID && eID == endID)
                    {
                        ed = v;
                        break;
                    }
                }
                edgeArticulations.put(ed, points);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        finally
        {
        	//try to close the file and return what was processed
        	try {
				pipe.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
        return LayoutPositions.createNewPositions(newVertexLocations, edgeArticulations);
    }
}
