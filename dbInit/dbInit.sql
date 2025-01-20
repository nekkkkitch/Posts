SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


create schema if not exists public;

alter schema public owner to pg_database_owner;

SET search_path TO public;

DROP EXTENSION IF EXISTS "uuid-ossp";

CREATE EXTENSION "uuid-ossp" SCHEMA public;

create table users if not exists(
    id uuid not null primary key default uuid_generate_v4(),
    login varchar(20) not null,
    password bytea[],
    mail varchar(256),
    verified boolean default false,
    refresh_token text not null
);

create table posts if not exists(
    id uuid not null primary key default uuid_generate_v4(),
    title varchar(256) not null,
    description varchar(5000),
    owner varchar(20) references public.users(login),
    date_of_creation date default NOW()
);

create table subs if not exists(
    creator varchar(20) references public.users(login),
    follower uuid references public.users(id),
    unique(creator, followerd)
)