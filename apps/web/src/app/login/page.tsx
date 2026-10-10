
"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";

export default function LoginPage() {
  const router = useRouter();

  const [isSignup, setIsSignup] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setError("");
    setLoading(true);

    try {
      const supabase = createSupabaseBrowserClient();

      if (isSignup) {
        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            emailRedirectTo: `${window.location.origin}/`,
          },
        });

        if (error) {
          throw error;
        }

        if (data.session) {
          router.push("/");
          router.refresh();
        } else {
          setMessage(
            "Account request received. Check your email to confirm your account before signing in."
          );
        }
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });

        if (error) {
          throw error;
        }

        router.push("/");
        router.refresh();
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Authentication failed. Please try again."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <Link
          className="brand"
          href="/"
          aria-label="ContractShield home"
        >
          <span className="brand-name">
            contract<span>shield</span>
          </span>
        </Link>

        <span className="product-label">
          SMART CONTRACT SECURITY
        </span>
      </header>

      <section
        className="page-content"
        style={{ maxWidth: 520 }}
      >
        <div className="intro">
          <span className="eyebrow">
            <span /> ACCOUNT ACCESS
          </span>

          <h1>
            {isSignup ? "Create your account." : "Welcome back."}
            <br />
            <span>
              {isSignup
                ? "Secure your workflow."
                : "Continue your review."}
            </span>
          </h1>

          <p>
            Sign in to ContractShield AI or create an account to get
            started.
          </p>
        </div>

        <form
          className="source-panel"
          onSubmit={handleSubmit}
        >
          <div className="panel-header">
            <div>
              <span className="step-label">
                CONTRACTSHIELD ACCOUNT
              </span>
              <h2>{isSignup ? "Sign up" : "Sign in"}</h2>
            </div>
          </div>

          <label className="source-label" htmlFor="email">
            Email address
          </label>

          <input
            id="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            style={{
              width: "100%",
              marginBottom: 18,
              padding: 12,
            }}
          />

          <label className="source-label" htmlFor="password">
            Password
          </label>

          <input
            id="password"
            type="password"
            autoComplete={
              isSignup ? "new-password" : "current-password"
            }
            minLength={6}
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            style={{
              width: "100%",
              marginBottom: 18,
              padding: 12,
            }}
          />

          {error && (
            <p className="error-message" role="alert">
              {error}
            </p>
          )}

          {message && <p role="status">{message}</p>}

          <button
            className="analyze-button"
            type="submit"
            disabled={loading}
            style={{ width: "100%" }}
          >
            {loading
              ? "Please wait..."
              : isSignup
                ? "Create account"
                : "Sign in"}
          </button>

          <p style={{ marginTop: 20 }}>
            {isSignup
              ? "Already have an account?"
              : "New to ContractShield AI?"}{" "}

            <button
              type="button"
              className="clear-button"
              onClick={() => {
                setIsSignup((current) => !current);
                setMessage("");
                setError("");
              }}
            >
              {isSignup ? "Sign in" : "Create an account"}
            </button>
          </p>
        </form>
      </section>
    </main>
  );
}