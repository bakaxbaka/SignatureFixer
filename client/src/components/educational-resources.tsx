import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { BookOpen, Shield, Key, ShieldAlert, ExternalLink } from "lucide-react";

interface EducationalContent {
  id: string;
  title: string;
  category: string;
  content: string;
  difficulty: string;
  tags: string[];
  viewCount: number;
}

export function EducationalResources() {
  const { toast } = useToast();

  const { data: content, isLoading } = useQuery<{ data: EducationalContent[] }>({
    queryKey: ['/api/educational-content'],
    staleTime: 300000, // Cache for 5 minutes
  });

  const incrementView = useMutation({
    mutationFn: async (contentId: string) => {
      await apiRequest('POST', `/api/educational-content/${contentId}/view`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/educational-content'] });
    },
  });

  const getTopicIcon = (category: string) => {
    switch (category) {
      case 'vulnerability': return <ShieldAlert className="w-4 h-4 text-destructive" />;
      case 'prevention': return <Shield className="w-4 h-4 text-green-500" />;
      case 'mathematics': return <Key className="w-4 h-4 text-orange-500" />;
      default: return <BookOpen className="w-4 h-4 text-primary" />;
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'bg-green-500/10 text-green-500 border-green-500/20';
      case 'intermediate': return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
      case 'advanced': return 'bg-red-500/10 text-red-500 border-red-500/20';
      default: return 'bg-muted/10 text-muted-foreground border-border';
    }
  };

  const handleTopicClick = (contentItem: EducationalContent) => {
    incrementView.mutate(contentItem.id);
    toast({
      title: contentItem.title,
      description: "Educational content would open in a modal or new page",
    });
  };

  // Static educational topics as fallback
  const staticTopics = [
    {
      id: '1',
      title: 'ECDSA Nonce Reuse',
      category: 'vulnerability',
      difficulty: 'intermediate',
      description: 'Understanding the mathematical vulnerability',
      content: 'Mathematical explanation of ECDSA nonce reuse attacks...',
      tags: ['ecdsa', 'nonce', 'vulnerability'],
      viewCount: 142
    },
    {
      id: '2',
      title: 'Private Key Recovery',
      category: 'mathematics',
      difficulty: 'advanced',
      description: 'Mathematical methods and algorithms',
      content: 'Deep dive into private key recovery techniques...',
      tags: ['cryptography', 'mathematics', 'recovery'],
      viewCount: 89
    },
    {
      id: '3',
      title: 'Prevention Methods',
      category: 'prevention',
      difficulty: 'beginner',
      description: 'RFC 6979 and secure implementations',
      content: 'Best practices for secure nonce generation...',
      tags: ['security', 'prevention', 'rfc6979'],
      viewCount: 203
    }
  ];

  const topics = content?.data || staticTopics;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-primary" />
          Educational Resources
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="p-3 border border-muted rounded-lg animate-pulse">
                <div className="flex items-center gap-3">
                  <div className="w-4 h-4 bg-muted rounded" />
                  <div className="flex-1">
                    <div className="h-4 w-32 bg-muted rounded mb-1" />
                    <div className="h-3 w-48 bg-muted rounded" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          topics.map((topic) => (
            <Button
              key={topic.id}
              variant="ghost"
              className="w-full text-left p-3 h-auto hover:bg-muted rounded-lg transition-colors"
              onClick={() => handleTopicClick(topic)}
              data-testid={`educational-topic-${topic.id}`}
            >
              <div className="flex items-start gap-3 w-full">
                {getTopicIcon(topic.category)}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-sm font-medium text-foreground truncate">
                      {topic.title}
                    </p>
                    <Badge variant="outline" className={getDifficultyColor(topic.difficulty)}>
                      {topic.difficulty}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-2">
                    {(topic as any).description || topic.content.substring(0, 100)}
                  </p>
                  <div className="flex items-center gap-2 mt-2">
                    {topic.tags && topic.tags.slice(0, 2).map((tag, index) => (
                      <Badge key={index} variant="secondary" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                    <span className="text-xs text-muted-foreground ml-auto">
                      {topic.viewCount} views
                    </span>
                  </div>
                </div>
                <ExternalLink className="w-3 h-3 text-muted-foreground flex-shrink-0" />
              </div>
            </Button>
          ))
        )}
        
        <div className="pt-3 border-t border-border">
          <Button variant="outline" size="sm" className="w-full" data-testid="button-view-all-resources">
            View All Resources
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
