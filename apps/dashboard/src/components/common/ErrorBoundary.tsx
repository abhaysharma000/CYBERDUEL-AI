import { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RotateCw } from "lucide-react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught render error:", error, errorInfo);
  }

  private handleReload = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[50vh] flex flex-col items-center justify-center p-8 text-center font-mono">
          <div className="w-14 h-14 rounded-2xl bg-red-950/60 border border-red-500/40 flex items-center justify-center text-red-400 mb-4 shadow-lg shadow-red-950/40">
            <AlertTriangle className="w-7 h-7" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">TELEMETRY RENDER EXCEPTION</h2>
          <p className="text-sm text-slate-400 max-w-md mb-4">
            A temporary contract discrepancy occurred while rendering this interface.
          </p>
          <div className="text-xs bg-[#120a0d] text-rose-300 p-3 rounded-lg border border-red-900/40 mb-6 max-w-lg overflow-x-auto text-left">
            {this.state.error?.message || "Unknown client runtime error"}
          </div>
          <button
            onClick={this.handleReload}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow-lg shadow-red-900/30 transition-colors"
          >
            <RotateCw className="w-4 h-4" />
            RELOAD CONSOLE
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
