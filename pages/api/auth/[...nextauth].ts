import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { compare } from "bcrypt";

import prismadb from "@/lib/prismadb";

export default NextAuth({
  providers: [
    Credentials({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: {
          label: "Email",
          type: "text",
        },
        password: {
          label: "Password",
          type: "password",
        },
      },
      async authorize(credentials) {
        if (!credentials?.email) {
          throw new Error("Please enter a valid email.");
        }
        if (!credentials?.password) {
          throw new Error(
            "Your password must contain between 4 and 60 characters."
          );
        }

        const user = await prismadb.user.findUnique({
          where: {
            email: credentials.email,
          },
        });

        if (!user || !user.hashedPassword) {
          throw new Error("An account with this Email does not exist.");
        }

        const isCorrectPasword = await compare(
          credentials.password,
          user.hashedPassword
        );

        if (!isCorrectPasword) {
          throw new Error(`Incorrect password for ${credentials.email}`);
        }

        return user;
      },
    }),
  ],
  pages: {
    signIn: "/auth",
  },
  debug: process.env.NODE_ENV === "development",
  session: {
    strategy: "jwt",
  },
  jwt: {
    secret: process.env.NEXTAUTH_JWT_SECRET,
  },
  secret: process.env.NEXTAUTH_SECRET,
});
