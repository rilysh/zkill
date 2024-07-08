#!/usr/bin/env bash

for i in {1..10}; do
    ../a.out loo
done

for i in {1..1000}; do
    ../a.out -er loopx
done

for i in {1..10000}; do
    ../a.out loo
done
