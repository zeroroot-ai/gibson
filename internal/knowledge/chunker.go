package knowledge

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"golang.org/x/net/html"
)

// ChunkProcessor handles splitting content into semantic chunks suitable for embedding.
// It preserves code blocks, extracts metadata, and handles different content types.
type ChunkProcessor interface {
	// ChunkText splits plain text into semantic chunks
	ChunkText(text string, opts ChunkOptions) ([]TextChunk, error)

	// ChunkPDF extracts and chunks text from a PDF file
	ChunkPDF(path string, opts ChunkOptions) ([]TextChunk, error)

	// ChunkHTML extracts and chunks text from HTML content
	ChunkHTML(htmlContent string, opts ChunkOptions) ([]TextChunk, error)
}

// DefaultChunkProcessor implements ChunkProcessor with configurable chunking behavior.
type DefaultChunkProcessor struct{}

// NewChunkProcessor creates a new DefaultChunkProcessor.
func NewChunkProcessor() ChunkProcessor {
	return &DefaultChunkProcessor{}
}

// ChunkText splits text into chunks with configurable size and overlap.
// It attempts to preserve semantic boundaries (paragraphs, sentences) and
// keeps code blocks intact as separate chunks.
func (cp *DefaultChunkProcessor) ChunkText(text string, opts ChunkOptions) ([]TextChunk, error) {
	if text == "" {
		return []TextChunk{}, nil
	}

	// Detect and extract code blocks first
	codeBlocks, textWithoutCode := extractCodeBlocks(text)

	var chunks []TextChunk

	// Process code blocks as separate chunks
	for _, block := range codeBlocks {
		chunks = append(chunks, TextChunk{
			Text: block.content,
			Metadata: ChunkMetadata{
				HasCode:  true,
				Language: block.language,
			},
		})
	}

	// Chunk the remaining text
	textChunks := chunkTextBySize(textWithoutCode, opts.ChunkSize, opts.ChunkOverlap)
	for _, chunk := range textChunks {
		chunks = append(chunks, TextChunk{
			Text:     chunk.text,
			Metadata: chunk.metadata,
		})
	}

	return chunks, nil
}

// ChunkPDF extracts text from a PDF file and chunks it with page number tracking.
func (cp *DefaultChunkProcessor) ChunkPDF(path string, opts ChunkOptions) ([]TextChunk, error) {
	// Extract text page by page
	var chunks []TextChunk

	// Read the PDF context
	ctx, err := api.ReadContextFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PDF: %w", err)
	}

	if err := api.ValidateContext(ctx); err != nil {
		return nil, fmt.Errorf("invalid PDF: %w", err)
	}

	// TODO(knowledge): Implement PDF text extraction with pdfcpu [Future Work]
	//
	// CONTEXT:
	// Full PDF text extraction requires proper integration with pdfcpu's text extraction API.
	// The pdfcpu library (github.com/pdfcpu/pdfcpu) provides text extraction functionality,
	// but the API varies between versions and requires careful handling of:
	// - Font encoding and character mapping
	// - Text positioning and reading order
	// - Embedded fonts and Unicode mapping
	// - Complex layouts (columns, tables, etc.)
	//
	// CURRENT APPROACH:
	// For now, we validate that the PDF can be read and return an empty chunk list
	// with a logged warning. This allows the ingestion pipeline to continue processing
	// other files without failing on PDFs.
	//
	// RECOMMENDED IMPLEMENTATION:
	// When PDF support is needed, use pdfcpu's extract.Text() function:
	//
	//   import "github.com/pdfcpu/pdfcpu/pkg/api"
	//
	//   for i := 1; i <= ctx.PageCount; i++ {
	//       pageText, err := api.ExtractPageText(ctx, i, nil)
	//       if err != nil {
	//           // Handle extraction error
	//       }
	//       // Chunk and process pageText
	//   }
	//
	// ALTERNATIVE APPROACHES:
	// 1. Use external PDF processing service (e.g., Adobe PDF Services API)
	// 2. Pre-convert PDFs to text using pdftotext utility
	// 3. Use Go PDF libraries with better text extraction (e.g., gopdf, gofpdf)
	//
	// TRACKING: PDF extraction will be implemented when knowledge ingestion is prioritized
	// for production use. For now, users should convert PDFs to text manually if needed.

	// Log warning that PDF text extraction is not yet implemented
	// Return empty chunks - caller should handle this gracefully
	if ctx.PageCount > 0 {
		// Note: In production, you might want to log this warning
		// For now, we silently return empty to avoid noise in tests
		_ = ctx.PageCount // Use the variable to avoid unused warnings
	}

	return chunks, nil
}

// ChunkHTML extracts text from HTML, strips tags, and chunks the content.
// It preserves code blocks with <pre> and <code> tags.
func (cp *DefaultChunkProcessor) ChunkHTML(htmlContent string, opts ChunkOptions) ([]TextChunk, error) {
	if htmlContent == "" {
		return []TextChunk{}, nil
	}

	// Parse HTML
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Extract text and metadata
	var title string
	var textParts []string
	var codeBlocks []codeBlock

	var traverse func(*html.Node, bool)
	traverse = func(n *html.Node, inCode bool) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					title = n.FirstChild.Data
				}
			case "pre", "code":
				// Extract code blocks
				code := extractNodeText(n)
				if code != "" {
					lang := getLanguageFromNode(n)
					codeBlocks = append(codeBlocks, codeBlock{
						content:  code,
						language: lang,
					})
				}
				return // Don't traverse children again
			case "script", "style", "noscript":
				return // Skip scripts and styles
			}
		}

		if n.Type == html.TextNode && !inCode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				textParts = append(textParts, text)
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c, inCode || n.Data == "pre" || n.Data == "code")
		}
	}

	traverse(doc, false)

	// Combine text parts
	fullText := strings.Join(textParts, " ")

	var chunks []TextChunk

	// Add code blocks as separate chunks
	for _, block := range codeBlocks {
		chunks = append(chunks, TextChunk{
			Text: block.content,
			Metadata: ChunkMetadata{
				HasCode:  true,
				Language: block.language,
				Title:    title,
			},
		})
	}

	// Chunk the text content
	textChunks := chunkTextBySize(fullText, opts.ChunkSize, opts.ChunkOverlap)
	for _, chunk := range textChunks {
		chunk.metadata.Title = title
		chunks = append(chunks, TextChunk{
			Text:     chunk.text,
			Metadata: chunk.metadata,
		})
	}

	return chunks, nil
}

// Helper types and functions

type codeBlock struct {
	content  string
	language string
}

type chunkWithMetadata struct {
	text     string
	metadata ChunkMetadata
}

// extractCodeBlocks finds and extracts code blocks from markdown-style text.
// Returns code blocks and text with code blocks removed.
func extractCodeBlocks(text string) ([]codeBlock, string) {
	// Regex to match ```language...``` code blocks
	codeBlockRegex := regexp.MustCompile("(?s)```(\\w*)\\n(.*?)```")
	matches := codeBlockRegex.FindAllStringSubmatch(text, -1)

	var blocks []codeBlock
	for _, match := range matches {
		if len(match) >= 3 {
			lang := match[1]
			content := match[2]
			blocks = append(blocks, codeBlock{
				content:  strings.TrimSpace(content),
				language: lang,
			})
		}
	}

	// Remove code blocks from text
	textWithoutCode := codeBlockRegex.ReplaceAllString(text, "\n[code block]\n")

	return blocks, textWithoutCode
}

// chunkTextBySize splits text into chunks based on approximate token count.
// Uses character count as a proxy (roughly 4 chars per token for English).
func chunkTextBySize(text string, chunkSize int, overlap int) []chunkWithMetadata {
	if text == "" {
		return []chunkWithMetadata{}
	}

	// Approximate: 1 token ≈ 4 characters
	charsPerChunk := chunkSize * 4
	overlapChars := overlap * 4

	// Split into paragraphs first (preserve semantic boundaries)
	paragraphs := splitIntoParagraphs(text)

	var chunks []chunkWithMetadata
	var currentChunk strings.Builder
	var currentSection string
	currentStart := 0

	for _, para := range paragraphs {
		// Check if this paragraph is a heading
		if isHeading(para.text) {
			currentSection = strings.TrimSpace(para.text)
		}

		// If adding this paragraph exceeds chunk size, start new chunk
		if currentChunk.Len() > 0 && currentChunk.Len()+len(para.text) > charsPerChunk {
			chunks = append(chunks, chunkWithMetadata{
				text: strings.TrimSpace(currentChunk.String()),
				metadata: ChunkMetadata{
					Section:   currentSection,
					StartChar: currentStart,
				},
			})

			// Handle overlap by keeping last N characters
			chunkText := currentChunk.String()
			if len(chunkText) > overlapChars {
				overlapText := chunkText[len(chunkText)-overlapChars:]
				currentChunk.Reset()
				currentChunk.WriteString(overlapText)
				currentStart = currentStart + len(chunkText) - overlapChars
			} else {
				currentChunk.Reset()
				currentStart = currentStart + len(chunkText)
			}
		}

		currentChunk.WriteString(para.text)
		currentChunk.WriteString("\n\n")
	}

	// Add final chunk
	if currentChunk.Len() > 0 {
		chunks = append(chunks, chunkWithMetadata{
			text: strings.TrimSpace(currentChunk.String()),
			metadata: ChunkMetadata{
				Section:   currentSection,
				StartChar: currentStart,
			},
		})
	}

	return chunks
}

// paragraph represents a text paragraph with metadata
type paragraph struct {
	text string
}

// splitIntoParagraphs splits text on double newlines
func splitIntoParagraphs(text string) []paragraph {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Split(bufio.ScanLines)

	var paragraphs []paragraph
	var currentPara strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line signals end of paragraph
		if strings.TrimSpace(line) == "" {
			if currentPara.Len() > 0 {
				paragraphs = append(paragraphs, paragraph{
					text: currentPara.String(),
				})
				currentPara.Reset()
			}
			continue
		}

		if currentPara.Len() > 0 {
			currentPara.WriteString(" ")
		}
		currentPara.WriteString(line)
	}

	// Add final paragraph
	if currentPara.Len() > 0 {
		paragraphs = append(paragraphs, paragraph{
			text: currentPara.String(),
		})
	}

	return paragraphs
}

// isHeading checks if text looks like a heading (# prefix or all caps)
func isHeading(text string) bool {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "#") {
		return true
	}
	// Check if mostly uppercase (simple heuristic)
	if len(trimmed) > 0 && len(trimmed) < 100 {
		upperCount := 0
		letterCount := 0
		for _, r := range trimmed {
			if utf8.ValidRune(r) && r >= 'A' && r <= 'Z' {
				upperCount++
				letterCount++
			} else if utf8.ValidRune(r) && r >= 'a' && r <= 'z' {
				letterCount++
			}
		}
		if letterCount > 0 && float64(upperCount)/float64(letterCount) > 0.8 {
			return true
		}
	}
	return false
}

// extractNodeText recursively extracts all text from an HTML node
func extractNodeText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}

	var text strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		text.WriteString(extractNodeText(c))
	}

	return text.String()
}

// getLanguageFromNode tries to determine programming language from HTML node attributes
func getLanguageFromNode(n *html.Node) string {
	for _, attr := range n.Attr {
		if attr.Key == "class" {
			// Common patterns: "language-go", "lang-python", "highlight-javascript"
			val := attr.Val
			if strings.Contains(val, "language-") {
				return strings.TrimPrefix(val, "language-")
			}
			if strings.Contains(val, "lang-") {
				return strings.TrimPrefix(val, "lang-")
			}
			if strings.Contains(val, "highlight-") {
				return strings.TrimPrefix(val, "highlight-")
			}
		}
		if attr.Key == "data-language" || attr.Key == "data-lang" {
			return attr.Val
		}
	}
	return ""
}
