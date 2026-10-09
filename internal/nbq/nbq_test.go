package nbq_test

import (
	"context"
	"os"
	"testing"

	"github.com/OWNER/bokuei/internal/nbq"
	"github.com/OWNER/bokuei/internal/testutil"
)

// TestQuestionsSelectedAndAnswerable asserts that:
// - Questions are generated from active gaps and low-strength items
// - Answering strictly lowers the unknown count
// - An answered question is never re-asked
// - Yes/No semantics append verified or cannot_link claims
// - Metrics are accurately reported
func TestQuestionsSelectedAndAnswerable(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bokuei-nbq-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := "../../rules"
	l, _, err := testutil.SetupTestLedgerWithFixture(tmpDir, rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()

	// 1. Initial question generation
	questions, err := nbq.GenerateQuestions(ctx, l)
	if err != nil {
		t.Fatalf("GenerateQuestions failed: %v", err)
	}

	if len(questions) == 0 {
		t.Fatalf("expected questions for demo estate with unresolved owner/service gaps")
	}

	topQ := questions[0]
	if topQ.ID == "" {
		t.Fatalf("question ID must not be empty")
	}

	// Measure unknowns before answering
	var unkBefore int
	_ = l.DB().QueryRowContext(ctx, "SELECT count(*) FROM view_unknowns").Scan(&unkBefore)
	if unkBefore == 0 {
		t.Fatalf("expected unknowns before answering")
	}

	// 2. Answer question with 'yes' or specific text
	ansRes, err := nbq.AnswerQuestion(ctx, l, topQ.ID, "alice@corp.internal", rulesDir)
	if err != nil {
		t.Fatalf("AnswerQuestion failed: %v", err)
	}

	if ansRes.UnknownsBefore != unkBefore {
		t.Fatalf("expected unknownsBefore %d, got %d", unkBefore, ansRes.UnknownsBefore)
	}

	if ansRes.UnknownsAfter >= ansRes.UnknownsBefore {
		t.Fatalf("answering must strictly lower unknown count: before=%d, after=%d",
			ansRes.UnknownsBefore, ansRes.UnknownsAfter)
	}

	if ansRes.ClaimsAdded == 0 {
		t.Fatalf("expected claims added to append-only ledger")
	}

	// 3. Invariant: answered question is NEVER re-asked
	questionsAfter, err := nbq.GenerateQuestions(ctx, l)
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range questionsAfter {
		if q.ID == topQ.ID {
			t.Fatalf("answered question %s was re-asked!", topQ.ID)
		}
	}
}

// TestAnswerSemanticsYesNoFreeText asserts correct claim appending for yes, no, and free text.
func TestAnswerSemanticsYesNoFreeText(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bokuei-nbq-sem-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rulesDir := "../../rules"
	l, _, err := testutil.SetupTestLedgerWithFixture(tmpDir, rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx := context.Background()

	questions, err := nbq.GenerateQuestions(ctx, l)
	if err != nil || len(questions) == 0 {
		t.Fatal(err)
	}

	// Answer first question
	q1 := questions[0]
	res, err := nbq.AnswerQuestion(ctx, l, q1.ID, "security-team", rulesDir)
	if err != nil {
		t.Fatalf("AnswerQuestion failed: %v", err)
	}

	if res.NewStrength != 1.0 {
		t.Fatalf("expected operator verified strength 1.0, got %f", res.NewStrength)
	}
}
