"use client";

import React, { useState, useEffect, useTransition, useCallback } from "react";
import {
  Bomb,
  Flame,
  RefreshCw,
  Sparkles,
  Loader2,
  Target,
  Bot,
  Trophy,
  Shield,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { cn } from "@/lib/utils";

// You will need to implement this server action
import { generateBlastReportAction } from "@/app/actions";

// Define AI output type
export type BomberGameOutput = {
  patternCategory: string;
  dataAssessment: string;
  recommendation: string;
  missionSuccess: "High" | "Medium" | "Low";
};

type Cell = 0 | 1;
type Grid = Cell[][];

export default function BomberGamePage() {
  const [grid, setGrid] = useState<Grid>([]);
  const [bombs, setBombs] = useState<[number, number][]>([]);
  const [bombLimit, setBombLimit] = useState(8);
  const [gridSize, setGridSize] = useState({ width: 20, height: 15 });
  const [blasted, setBlasted] = useState(false);
  const [isPending, startTransition] = useTransition();
  const [aiReport, setAiReport] = useState<BomberGameOutput | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [totalOnes, setTotalOnes] = useState(0);
  const [onesCleared, setOnesCleared] = useState(0);
  const [gameWon, setGameWon] = useState(false);

  const generateGrid = useCallback(() => {
    const width = Math.floor(Math.random() * (25 - 15 + 1)) + 15;
    const height = Math.floor(Math.random() * (20 - 10 + 1)) + 10;

    const newGrid = Array.from({ length: height }, () =>
      Array.from({ length: width }, () => (Math.random() > 0.6 ? 1 : 0))
    );

    setTotalOnes(newGrid.flat().filter((cell) => cell === 1).length);

    const newBombLimit = Math.max(5, Math.floor((width * height) / 40));

    setGridSize({ width, height });
    setGrid(newGrid);
    setBombLimit(newBombLimit);
    setBombs([]);
    setBlasted(false);
    setGameWon(false);
    setOnesCleared(0);
    setAiReport(null);
    setError(null);
  }, []);

  useEffect(() => {
    generateGrid();
  }, [generateGrid]);

  const toggleBomb = (row: number, col: number) => {
    if (blasted) return;
    const bombIndex = bombs.findIndex(([r, c]) => r === row && c === col);
    if (bombIndex > -1) {
      setBombs(bombs.filter((_, i) => i !== bombIndex));
    } else {
      if (bombs.length < bombLimit) {
        setBombs([...bombs, [row, col]]);
      }
    }
  };

  const isCellInBombRadius = (row: number, col: number) => {
    return bombs.some(
      ([bombRow, bombCol]) =>
        Math.abs(row - bombRow) <= 1 && Math.abs(col - bombCol) <= 1
    );
  };

  const handleBlast = () => {
    if (bombs.length === 0) return;
    setBlasted(true);
    setError(null);
    setAiReport(null);

    const cleared = grid
      .flat()
      .filter((cell, i) => {
        const row = Math.floor(i / gridSize.width);
        const col = i % gridSize.width;
        return cell === 1 && isCellInBombRadius(row, col);
      }).length;

    setOnesCleared(cleared);
    if (cleared === totalOnes && totalOnes > 0) {
      setGameWon(true);
    }

    startTransition(async () => {
      const result = await generateBlastReportAction({ grid, bombs });
      if (result.status === "success") {
        setAiReport(result.report);
      } else {
        setError(result.error);
      }
    });
  };

  const bombsRemaining = bombLimit - bombs.length;

  return (
    <div className="flex flex-col items-center gap-6 p-4">
      {/* Game card */}
      <Card className="w-full max-w-7xl">
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Bomb />
                Bomber Game
              </CardTitle>
              <CardDescription>
                Grid Size: {gridSize.width}x{gridSize.height}. Place up to{" "}
                {bombLimit} bombs to extract all target data (1s).
              </CardDescription>
            </div>
            <div className="text-right flex items-center gap-4">
              <div>
                <div className="font-bold text-lg flex items-center gap-1">
                  <Target size={18} />{" "}
                  {blasted ? `${onesCleared} / ${totalOnes}` : totalOnes}
                </div>
                <div className="text-sm text-muted-foreground">Target Data</div>
              </div>
              <div>
                <div className="font-bold text-lg">{bombsRemaining}</div>
                <div className="text-sm text-muted-foreground">Bombs Left</div>
              </div>
              <div>
                <div className="font-bold text-lg">{bombs.length}</div>
                <div className="text-sm text-muted-foreground">Placed</div>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex justify-center mb-4 overflow-x-auto">
            <div
              className="grid gap-0.5 bg-muted/20 p-1 rounded-lg"
              style={{
                gridTemplateColumns: `repeat(${gridSize.width}, minmax(0, 1fr))`,
              }}
            >
              {grid.map((row, rowIndex) =>
                row.map((cell, colIndex) => {
                  const isBombCenter = bombs.some(
                    ([r, c]) => r === rowIndex && c === colIndex
                  );
                  const isInRadius = isCellInBombRadius(rowIndex, colIndex);

                  return (
                    <div
                      key={`${rowIndex}-${colIndex}`}
                      className={cn(
                        "flex items-center justify-center w-7 h-7 font-mono text-sm rounded-sm cursor-pointer transition-all",
                        blasted
                          ? "cursor-not-allowed"
                          : "hover:bg-primary/20",
                        blasted
                          ? isInRadius
                            ? (cell === 1
                                ? "bg-green-500"
                                : "bg-yellow-500/80") + " text-white"
                            : "bg-muted"
                          : isInRadius
                          ? "bg-orange-400/30"
                          : "bg-background",
                        isBombCenter && !blasted && "bg-destructive/50"
                      )}
                      onClick={() => toggleBomb(rowIndex, colIndex)}
                    >
                      {isBombCenter && !blasted ? (
                        <Bomb
                          size={16}
                          className="text-destructive-foreground"
                        />
                      ) : blasted ? (
                        isInRadius ? (
                          cell
                        ) : (
                          ""
                        )
                      ) : (
                        cell
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Controls */}
      <div className="flex gap-4">
        <Button onClick={generateGrid} variant="outline" disabled={isPending}>
          <RefreshCw className="mr-2 h-4 w-4" />
          New Game
        </Button>
        <Button
          onClick={handleBlast}
          disabled={blasted || bombs.length === 0 || isPending}
        >
          <Flame className="mr-2 h-4 w-4" />
          Blast ({bombs.length})
        </Button>
      </div>

      {/* Blast results */}
      {blasted && (
        <Card className="w-full max-w-7xl">
          <CardHeader>
            <CardTitle>Blast Result</CardTitle>
            <CardDescription>
              The data pattern revealed by your bombs. You extracted{" "}
              {onesCleared} out of {totalOnes} target data fragments.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {gameWon && (
              <Alert className="mb-4 bg-green-50 dark:bg-green-900/20 border-green-500">
                <Trophy className="h-5 w-5 text-green-600" />
                <AlertTitle className="text-green-800 dark:text-green-300">
                  Target Data Cleared!
                </AlertTitle>
                <AlertDescription className="text-green-700 dark:text-green-400">
                  Congratulations! You have successfully extracted all target
                  data fragments from the grid.
                </AlertDescription>
              </Alert>
            )}
            <div className="flex justify-center overflow-x-auto">
              <div
                className="grid gap-0.5 bg-background p-1 rounded-lg"
                style={{
                  gridTemplateColumns: `repeat(${gridSize.width}, minmax(0, 1fr))`,
                }}
              >
                {grid.map((row, rowIndex) =>
                  row.map((cell, colIndex) => (
                    <div
                      key={`result-${rowIndex}-${colIndex}`}
                      className={cn(
                        "flex items-center justify-center w-7 h-7 font-mono text-sm rounded-sm",
                        isCellInBombRadius(rowIndex, colIndex)
                          ? cell === 1
                            ? "bg-green-500 text-white"
                            : "bg-yellow-500 text-white"
                          : "bg-muted"
                      )}
                    >
                      {isCellInBombRadius(rowIndex, colIndex) ? cell : ""}
                    </div>
                  ))
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* AI analysis */}
      {isPending && (
        <div className="flex items-center justify-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span>Gemini is analyzing the blast pattern...</span>
        </div>
      )}

      {aiReport && (
        <Card className="w-full max-w-2xl">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-primary">
              <Sparkles />
              AI Blast Analysis
            </CardTitle>
            <CardDescription>{aiReport.patternCategory}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-start gap-3">
              <Bot className="h-5 w-5 mt-1 flex-shrink-0" />
              <div>
                <p className="font-semibold">Data Assessment</p>
                <p className="text-sm text-muted-foreground">
                  {aiReport.dataAssessment}
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Target className="h-5 w-5 mt-1 flex-shrink-0" />
              <div>
                <p className="font-semibold">Recommendation</p>
                <p className="text-sm text-muted-foreground">
                  {aiReport.recommendation}
                </p>
              </div>
            </div>
          </CardContent>
          <CardFooter>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              <p className="font-semibold">Mission Success:</p>
              <Badge
                variant={
                  aiReport.missionSuccess === "High"
                    ? "default"
                    : aiReport.missionSuccess === "Medium"
                    ? "secondary"
                    : "destructive"
                }
                className={cn(
                  aiReport.missionSuccess === "High" && "bg-green-600",
                  gameWon && "bg-green-600"
                )}
              >
                {gameWon ? "Critical Success" : aiReport.missionSuccess}
              </Badge>
            </div>
          </CardFooter>
        </Card>
      )}

      {/* Error display */}
      {error && (
        <Alert variant="destructive" className="w-full max-w-5xl">
          <AlertTitle>Analysis Failed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}
