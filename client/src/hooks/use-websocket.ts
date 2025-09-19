import { useState, useEffect, useRef } from "react";
import { useToast } from "@/hooks/use-toast";

interface WebSocketMessage {
  type: string;
  [key: string]: any;
}

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;
  const { toast } = useToast();

  const connect = () => {
    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        setIsConnected(true);
        setConnectionError(null);
        reconnectAttempts.current = 0;
        console.log('WebSocket connected');
      };

      wsRef.current.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as WebSocketMessage;
          setLastMessage(message);
          
          // Handle specific message types
          switch (message.type) {
            case 'utxo_analysis':
              toast({
                title: "UTXO Analysis Update",
                description: `Found ${message.utxoCount} UTXOs for address`,
              });
              break;
              
            case 'vulnerability_analysis':
              toast({
                title: "Vulnerability Detected",
                description: `${message.vulnerabilityCount} vulnerabilities found, ${message.criticalIssues} critical`,
                variant: message.criticalIssues > 0 ? "destructive" : "default",
              });
              break;
              
            case 'batch_progress':
              toast({
                title: "Batch Analysis Progress",
                description: `${message.progress}% complete (${message.processedCount} addresses)`,
              });
              break;
              
            case 'batch_completed':
              toast({
                title: "Batch Analysis Complete",
                description: `Processed ${message.totalProcessed} addresses, found ${message.totalVulnerabilities} vulnerabilities`,
              });
              break;
              
            case 'batch_error':
              toast({
                title: "Batch Analysis Error",
                description: message.error,
                variant: "destructive",
              });
              break;
              
            default:
              console.log('Received WebSocket message:', message);
          }
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        setConnectionError('Connection error occurred');
      };

      wsRef.current.onclose = () => {
        setIsConnected(false);
        console.log('WebSocket disconnected');
        
        // Attempt to reconnect
        if (reconnectAttempts.current < maxReconnectAttempts) {
          reconnectAttempts.current++;
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
          setTimeout(() => {
            console.log(`Attempting to reconnect... (${reconnectAttempts.current}/${maxReconnectAttempts})`);
            connect();
          }, delay);
        } else {
          setConnectionError('Failed to reconnect after multiple attempts');
        }
      };
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      setConnectionError('Failed to create connection');
    }
  };

  const disconnect = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  };

  const sendMessage = (message: WebSocketMessage) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected');
    }
  };

  useEffect(() => {
    connect();
    
    return () => {
      disconnect();
    };
  }, []);

  return {
    isConnected,
    lastMessage,
    connectionError,
    sendMessage,
    reconnect: connect,
    disconnect,
  };
}
